#![no_std]
#![forbid(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use aes_gcm::aead::arrayvec::ArrayVec;
use dummy_pin::DummyPin;
use embedded_hal::digital::ErrorType as GpioErrorType;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::ErrorType as SpiErrorType;
use embedded_hal::spi::SpiDevice;
use nom::Needed;
use nom_derive::Parse;
use packed_struct::PackingError;
use packed_struct::derive::PackedStruct;
use zerocopy::IntoBytes;
use zeroize::Zeroize;

pub use crate::crypto::CryptoError;
pub use crate::crypto::X25519;
#[cfg(feature = "x25519-dalek")]
pub use crate::crypto::X25519Dalek;
pub use crate::lt_2::ResponseStatus;
pub use crate::lt_2::SleepReq;
pub use crate::lt_2::StartupReq;
pub use crate::lt_2::X509Certificate;
pub use crate::lt_3::EccCurve;
pub use crate::lt_3::EccKeyReadResponse;
pub use crate::lt_3::EccOrigin;

mod crc16;
mod crypto;
#[cfg(feature = "keys")]
pub mod keys;
mod lt_1;
mod lt_2;
mod lt_3;

/// Max number of retries when reading from chip
const L1_READ_MAX_TRIES: usize = 50;
/// Max number of data bytes in one L1 transfer
const _L1_LEN_MAX: usize = 1 + 1 + 1 + L2_CHUNK_MAX_DATA_SIZE + 2;

/// Max size of data field in one L2 transfer
const L2_CHUNK_MAX_DATA_SIZE: usize = 252;
/// Max size of one L2 frame
const L2_MAX_FRAME_SIZE: usize = 1 + 1 + L2_CHUNK_MAX_DATA_SIZE + 2;
const L2_CMD_REQ_LEN: usize = 128;

/// Size of the `id` field in L3 commands
const L3_CMD_ID_SIZE: usize = 1;
/// Size of the `tag` field in L3 commands
const L3_TAG_SIZE: usize = 16;
/// Max size of the `data` field in L3 commands and result packets
const L3_CMD_DATA_SIZE_MAX: usize = 4096;
/// Size of the `size` field in L3 commands
const L3_CMD_SIZE_SIZE: usize = size_of::<u16>();
/// Size of the `size` field in L3 result packets
const L3_RES_SIZE_SIZE: usize = size_of::<u16>();
/// Max size of the `ciphertext` field in L3 result packets
const L3_PACKET_MAX_SIZE: usize = L3_CMD_ID_SIZE + L3_CMD_DATA_SIZE_MAX;
/// Max size of an L3 frame
const L3_FRAME_MAX_SIZE: usize = L3_RES_SIZE_SIZE + L3_PACKET_MAX_SIZE + L3_TAG_SIZE;

/// Tropic01 driver
pub struct Tropic01<SPI, CS> {
    spi: SPI,
    l2_buf: [u8; L2_MAX_FRAME_SIZE + 1],
    l3_buf: ArrayVec<u8, L3_FRAME_MAX_SIZE>,
    cs: Option<CS>,
    session: Option<Session>,
}

impl<SPI: SpiDevice> Tropic01<SPI, DummyPin> {
    /// Takes a [SpiDevice] to create a new instance.
    ///
    /// If the [SpiDevice] does not handle the chip-select (CS) pin, use the
    /// [Self::with_cs_pin] method to specify a CS pin and have it managed by
    /// the [Tropic01] driver.
    ///
    /// It is recommended to configure the [SpiDevice] to use SPI mode 0 (CPOL =
    /// 0, CPHA = 0) with a clock speed of 5mHz and MSB sent first.
    pub fn new(spi: SPI) -> Self {
        Self {
            spi,
            l2_buf: [0; L2_MAX_FRAME_SIZE + 1],
            l3_buf: ArrayVec::new(),
            cs: None,
            session: None,
        }
    }
}

impl<SPI: SpiDevice, CS: OutputPin> Tropic01<SPI, CS> {
    /// Configure the driver to manage the chip-select pin. This is optional,
    /// use this if the [SpiDevice] does not handle the CS pin.
    pub fn with_cs_pin<CS2: OutputPin>(
        self,
        mut cs: CS2,
    ) -> Result<
        Tropic01<SPI, CS2>,
        Error<<SPI as SpiErrorType>::Error, <CS2 as GpioErrorType>::Error>,
    > {
        cs.set_high().map_err(Error::GPIOError)?;
        Ok(Tropic01 {
            spi: self.spi,
            l2_buf: self.l2_buf,
            l3_buf: self.l3_buf,
            cs: Some(cs),
            session: self.session,
        })
    }
}

#[derive(Debug, PackedStruct)]
#[packed_struct(size_bytes = "1", bit_numbering = "lsb0")]
struct ChipStatus {
    #[packed_field(bits = "0")]
    ready: bool,
    #[packed_field(bits = "1")]
    alarm: bool,
    #[packed_field(bits = "2")]
    start: bool,
}

/// Represents all kinds of parsing errors.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum ParsingError {
    #[display("Parsing failed: {_0:?}")]
    Error(#[error(not(source))] nom::error::ErrorKind),
    #[display("Parsing failed, needs more bytes: {_0:?}")]
    Needed(#[error(not(source))] Needed),
}

impl From<nom::Err<ParsingError>> for ParsingError {
    fn from(other: nom::Err<ParsingError>) -> Self {
        match other {
            nom::Err::Error(e) => e,
            nom::Err::Incomplete(e) => ParsingError::Needed(e),
            nom::Err::Failure(e) => e,
        }
    }
}

/// Convenience trait to auto-implement nom parsing for all T that derive `Nom`.
trait FromBytes<'a>
where
    Self: Sized,
{
    fn from_bytes(slice: &'a [u8]) -> Result<Self, ParsingError>;
}

impl<'a, T: Parse<&'a [u8]>> FromBytes<'a> for T {
    fn from_bytes(slice: &'a [u8]) -> Result<Self, ParsingError> {
        let (_, res) = T::parse(slice).map_err(|e| e.map(|e| ParsingError::Error(e.code)))?;
        Ok(res)
    }
}

/// Any type of error which may occur while interacting with the device
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum Error<ESpi, EGpio> {
    #[display("Chip is in alarm mode")]
    AlarmMode,
    /// Some error originating from the communication bus
    #[display("L1 communication failed because of SPI bus: {_0}")]
    BusError(ESpi),
    #[display("Chip seems to be busy")]
    ChipBusy,
    #[display("Error during decryption of the result")]
    Decryption(CryptoError),
    #[display("Error during encryption of a command")]
    Encryption(CryptoError),
    #[display("L1 communication failed because of GPIO bus: {_0}")]
    GPIOError(EGpio),
    #[display("Handshake failed")]
    HandshakeFailed,
    #[display("Unexpected chip status: {_0:?}")]
    InvalidChipStatus(#[error(not(source))] PackingError),
    #[display("Chip send response with invalid CRC")]
    InvalidCRC,
    #[display("The key in the requested slot does not exist")]
    InvalidKey,
    #[display(
        "Chip did not answer with a valid response (either due to a CRC not matching the response \
         or a generic error code from the chip)"
    )]
    InvalidL2Response,
    #[display("Chip has received an invalid L3 command")]
    InvalidL3Cmd,
    #[display("Invalid public key in chip certificate")]
    InvalidPublicKey,
    #[display("Error during processing of L2 cmd: {_0}")]
    L2ResponseError(ResponseStatus),
    #[display("Error during processing of L3 cmd")]
    L3CmdFailed,
    #[display("L3 response buffer overflow")]
    L3ResponseBufferOverflow,
    #[display("No secure session established")]
    NoSession,
    #[display("Parsing L3 response failed: {_0}")]
    ParsingError(ParsingError),
    #[display("Request exceeded allowed max size")]
    RequestExceedsSize,
    #[display("Insufficient user access privileges")]
    Unauthorized,
    #[display("Chip returned unexpected response status")]
    UnexpectedResponseStatus,
}

impl<ESpi, EGpio> From<ParsingError> for Error<ESpi, EGpio> {
    fn from(other: ParsingError) -> Self {
        Self::ParsingError(other)
    }
}

impl<SPI: SpiErrorType, CS: GpioErrorType> SpiErrorType for Tropic01<SPI, CS>
where
    Error<
        <SPI as embedded_hal::spi::ErrorType>::Error,
        <CS as embedded_hal::digital::ErrorType>::Error,
    >: embedded_hal::spi::Error + embedded_hal::digital::Error,
{
    type Error =
        Error<<SPI as SpiErrorType>::Error, <CS as embedded_hal::digital::ErrorType>::Error>;
}

impl<SPI: SpiErrorType, CS: GpioErrorType> GpioErrorType for Tropic01<SPI, CS>
where
    Error<
        <SPI as embedded_hal::spi::ErrorType>::Error,
        <CS as embedded_hal::digital::ErrorType>::Error,
    >: embedded_hal::spi::Error + embedded_hal::digital::Error,
{
    type Error =
        Error<<SPI as SpiErrorType>::Error, <CS as embedded_hal::digital::ErrorType>::Error>;
}

/// 256-bit key
#[derive(Zeroize)]
struct Aes256GcmKey([u8; 32]);

impl AsRef<[u8]> for Aes256GcmKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// 96-bit nonce
#[derive(Default, Zeroize)]
struct Nonce(u128);

impl Nonce {
    const MAX_U96: u128 = 2u128.pow(96) - 1;

    /// Increment by 1 with wrapping.
    const fn wrapping_inc(&mut self) {
        self.0 += 1;
        if self.0 > Self::MAX_U96 {
            self.0 = 1;
        }
    }
}
impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        let bytes = self.0.as_bytes();
        &bytes[..12]
    }
}

#[derive(Zeroize)]
struct Session {
    iv: Nonce,
    encrypt: Aes256GcmKey,
    decrypt: Aes256GcmKey,
}

impl Session {
    fn new(encrypt: Aes256GcmKey, decrypt: Aes256GcmKey) -> Self {
        Self {
            iv: Nonce::default(),
            encrypt,
            decrypt,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::Nonce;

    #[test]
    fn increment_nonce_works() {
        let mut expected = 1;
        let mut nonce = Nonce::default();
        nonce.wrapping_inc();
        assert_eq!(nonce.0, expected);
        for _ in 0..256 {
            nonce.wrapping_inc();
        }
        expected = 257;
        assert_eq!(nonce.0, expected);
    }
}
