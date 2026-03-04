use embedded_hal::digital::ErrorType as GpioErrorType;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::ErrorType as SpiErrorType;
use embedded_hal::spi::SpiDevice;
use zerocopy::IntoBytes;
use zerocopy::little_endian::U16;

use crate::Error;
use crate::FromBytes;
use crate::L3_CMD_DATA_SIZE_MAX;
use crate::L3_RES_SIZE_SIZE;
use crate::L3_TAG_SIZE;
use crate::ParsingError;
use crate::Tropic01;
use crate::crypto::aesgcm_decrypt;
use crate::crypto::aesgcm_encrypt;
use crate::lt_2::l2_receive_encrypted_cmd;
use crate::lt_2::l2_send_encrypted_cmd;
use crate::take;
use crate::take_le_u16;
use crate::take_u8;

#[derive(Clone, Debug)]
struct DecryptedL3CommandPacket<'a> {
    id: u8,
    data: &'a [&'a [u8]],
}

impl<'a> DecryptedL3CommandPacket<'a> {
    #[must_use]
    pub const fn new(id: u8, data: &'a [&'a [u8]]) -> Self {
        Self { id, data }
    }
}

#[derive(Clone, Debug)]
pub(super) struct EncryptedL3CommandPacket<'a> {
    cmd_size: U16,
    data: &'a [u8],
    tag: [u8; L3_TAG_SIZE],
}

impl<'a> EncryptedL3CommandPacket<'a> {
    #[must_use]
    pub const fn cmd_size(&self) -> U16 {
        self.cmd_size
    }

    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    #[must_use]
    pub const fn tag(&self) -> [u8; L3_TAG_SIZE] {
        self.tag
    }
}

#[derive(Debug)]
#[repr(u8)]
enum L3CmdId {
    Ping = 0x01,
    PairingKeyWrite = 0x10,
    PairingKeyRead = 0x11,
    PairingKeyInvalidate = 0x12,
    RConfigWrite = 0x20,
    RConfigRead = 0x21,
    RConfigErase = 0x22,
    IConfigWrite = 0x30,
    IConfigRead = 0x31,
    RMemDataWrite = 0x40,
    RMemDataRead = 0x41,
    RMemDataErase = 0x42,
    RandomValueGet = 0x50,
    EccKeyGenerate = 0x60,
    EccKeyStore = 0x61,
    EccKeyRead = 0x62,
    EccKeyErase = 0x63,
    EcDSASign = 0x70,
    EdDSASign = 0x71,
    MCounterInit = 0x80,
    MCounterUpdate = 0x81,
    MCounterGet = 0x82,
    MacAndDestroy = 0x90,
}

/// Maximum ECC slot index.
pub const ECC_SLOT_MAX: u16 = 31;
/// Maximum R_MEM_DATA slot index.
pub const R_MEM_DATA_SLOT_MAX: u16 = 511;
/// Maximum pairing key slot index.
pub const PAIRING_KEY_SLOT_MAX: u16 = 3;
/// Maximum MAC-and-destroy slot index.
pub const MAC_AND_DESTROY_SLOT_MAX: u16 = 127;

/// Represents all kinds of curves the chip supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::TryFrom)]
#[repr(u8)]
#[try_from(repr)]
pub enum EccCurve {
    P256 = 0x01,
    Ed25519 = 0x02,
}

impl<'a> FromBytes<'a> for EccCurve {
    fn from_bytes(slice: &'a [u8]) -> Result<Self, ParsingError> {
        let (_, b) = take_u8(slice)?;
        Ok(Self::try_from(b)?)
    }
}

/// Monotonic counter index (0-15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MCounterIndex {
    Index0 = 0,
    Index1 = 1,
    Index2 = 2,
    Index3 = 3,
    Index4 = 4,
    Index5 = 5,
    Index6 = 6,
    Index7 = 7,
    Index8 = 8,
    Index9 = 9,
    Index10 = 10,
    Index11 = 11,
    Index12 = 12,
    Index13 = 13,
    Index14 = 14,
    Index15 = 15,
}

/// Maximum allowed value for monotonic counter.
pub const MCOUNTER_VALUE_MAX: u32 = 0xFFFF_FFFE;

impl EccCurve {
    const fn key_len(self) -> usize {
        match self {
            EccCurve::Ed25519 => 32,
            EccCurve::P256 => 64,
        }
    }
}

#[derive(Debug)]
pub(super) struct L3ResultPacket<'a> {
    _size: u16,
    _ciphertext: &'a [u8],
    _tag: [u8; 16],
}

impl<'a> FromBytes<'a> for L3ResultPacket<'a> {
    fn from_bytes(slice: &'a [u8]) -> Result<Self, ParsingError> {
        let (rest, size) = take_le_u16(slice)?;
        let (rest, ciphertext) = take(rest, size as usize)?;
        let (_, tag_slice) = take(rest, 16)?;
        let tag: [u8; 16] = tag_slice
            .try_into()
            // Safety: take(16) guarantees exactly 16 bytes
            .expect("tag to be 16 bytes");
        Ok(Self {
            _size: size,
            _ciphertext: ciphertext,
            _tag: tag,
        })
    }
}

/// Decrypted result data.
///
/// This is the decrypted content of [L3ResultPacket]s `ciphertext` field.
#[derive(Debug)]
struct L3ResultData<'a> {
    result: L3ResultStatus,
    data: &'a [u8],
}

impl<'a> FromBytes<'a> for L3ResultData<'a> {
    fn from_bytes(slice: &'a [u8]) -> Result<Self, ParsingError> {
        let (rest, b) = take_u8(slice)?;
        let result = L3ResultStatus::try_from(b)?;
        Ok(Self { result, data: rest })
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    derive_more::TryFrom,
    derive_more::Display,
    derive_more::Error,
)]
#[repr(u8)]
#[try_from(repr)]
enum L3ResultStatus {
    Ok = 0xc3,
    Fail = 0x3c,
    Unauthorized = 0x01,
    InvalidCmd = 0x02,
    SlotNotEmpty = 0x10,
    SlotExpired = 0x11,
    InvalidKey = 0x12,
    UpdateErr = 0x13,
    CounterInvalid = 0x14,
    SlotEmpty = 0x15,
    SlotInvalid = 0x16,
    HardwareFail = 0x17,
}

/// Represents all kinds of origins the chip supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::TryFrom)]
#[repr(u8)]
#[try_from(repr)]
pub enum EccOrigin {
    /// Key originated from the [Tropic01::ecc_key_generate] method.
    KeyGenerate = 0x01,
    /// Key originated from the [Tropic01::ecc_key_read] method.
    KeyStore = 0x02,
}

#[derive(Debug, Clone)]
pub struct EccKeyReadResponse<'a> {
    curve: EccCurve,
    origin: EccOrigin,
    /// The public key. For P-256 curves, this is the uncompressed x + y
    /// coordinates.
    pub_key: &'a [u8],
}

impl<'a> FromBytes<'a> for EccKeyReadResponse<'a> {
    fn from_bytes(slice: &'a [u8]) -> Result<Self, ParsingError> {
        let (rest, curve_byte) = take_u8(slice)?;
        let curve = EccCurve::try_from(curve_byte)?;
        let (rest, origin_byte) = take_u8(rest)?;
        let origin = EccOrigin::try_from(origin_byte)?;
        let (rest, _) = take(rest, 13)?;
        let (_, pub_key) = take(rest, curve.key_len())?;
        Ok(Self {
            curve,
            origin,
            pub_key,
        })
    }
}

impl<'a> EccKeyReadResponse<'a> {
    #[must_use]
    pub const fn curve(&self) -> EccCurve {
        self.curve
    }

    #[must_use]
    pub const fn origin(&self) -> EccOrigin {
        self.origin
    }

    #[must_use]
    pub const fn pub_key(&self) -> &'a [u8] {
        self.pub_key
    }
}

#[derive(Debug, Clone)]
struct SignResponse<'a> {
    signature: &'a [u8],
}

impl<'a> FromBytes<'a> for SignResponse<'a> {
    fn from_bytes(slice: &'a [u8]) -> Result<Self, ParsingError> {
        let (rest, _) = take(slice, 15)?;
        let (_, signature) = take(rest, 64)?;
        Ok(Self { signature })
    }
}

impl<SPI: SpiDevice, CS: OutputPin> Tropic01<SPI, CS> {
    fn lt_l3_transfer(
        &mut self,
        packet: DecryptedL3CommandPacket<'_>,
    ) -> Result<L3ResultData<'_>, Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>>
    {
        let session = self.session.as_mut().ok_or_else(|| Error::NoSession)?;
        self.l3_buf.clear();

        self.l3_buf
            .try_extend_from_slice(&[packet.id])
            // Safety: Expect is safe here since it is verified before that l3_buf has enough capacity, and l3_buf was just emptied.
            .expect("packet id to fit into buffer");
        for data in packet.data {
            self.l3_buf
                .try_extend_from_slice(data)
                // Safety: This is safe since ping and eddsa_sign methods verify that their raw data does not exceed L3_CMD_DATA_SIZE_MAX.
                .expect("packet msg to fit into buffer");
        }
        let len = self.l3_buf.len();

        let size = U16::try_from(len)
        // Safety: Expect is safe here since l3_buf capacity (L3_FRAME_MAX_SIZE) < U16::MAX.
        .expect("cmd len to be in u16 range");
        let tag = aesgcm_encrypt(&session.encrypt, &session.iv, b"", &mut self.l3_buf)
            .map_err(Error::Encryption)?;

        let cmd = EncryptedL3CommandPacket {
            cmd_size: size,
            data: &self.l3_buf,
            tag,
        };

        l2_send_encrypted_cmd(cmd, &mut self.l2_buf, &mut self.spi, &mut self.cs)?;
        let _ = l2_receive_encrypted_cmd(
            &mut self.l2_buf,
            &mut self.l3_buf,
            &mut self.spi,
            &mut self.cs,
        )?;

        // Remove the tag and cmd_size from the l3_buf, leaving only the encrypted data.
        //
        // SAFETY: `drain` and `split_at_mut` are safe here because
        // `l2_receive_encrypted_cmd` validates `l3_buf` by parsing into
        // `L3ResultPacket``
        debug_assert!(self.l3_buf.len() > L3_RES_SIZE_SIZE + L3_TAG_SIZE);
        self.l3_buf.drain(0..L3_RES_SIZE_SIZE);
        let l3_buf_len = self.l3_buf.len();
        let (l3_buf, tag) = self.l3_buf.split_at_mut(l3_buf_len - L3_TAG_SIZE);

        aesgcm_decrypt(&session.decrypt, &session.iv, b"", tag, l3_buf)
            .map_err(Error::Decryption)?;

        session.iv.wrapping_inc();

        let res = L3ResultData::from_bytes(l3_buf)?;

        match res.result {
            L3ResultStatus::Ok => (),
            L3ResultStatus::Fail => return Err(Error::L3CmdFailed),
            L3ResultStatus::InvalidCmd => return Err(Error::InvalidL3Cmd),
            L3ResultStatus::InvalidKey => return Err(Error::InvalidKey),
            L3ResultStatus::Unauthorized => return Err(Error::Unauthorized),
            L3ResultStatus::SlotNotEmpty => return Err(Error::SlotNotEmpty),
            L3ResultStatus::SlotExpired => return Err(Error::SlotExpired),
            L3ResultStatus::UpdateErr => return Err(Error::UpdateErr),
            L3ResultStatus::CounterInvalid => return Err(Error::CounterInvalid),
            L3ResultStatus::SlotEmpty => return Err(Error::SlotEmpty),
            L3ResultStatus::SlotInvalid => return Err(Error::SlotInvalid),
            L3ResultStatus::HardwareFail => return Err(Error::HardwareFail),
        }

        Ok(res)
    }

    pub fn ping(
        &mut self,
        data: &[u8],
    ) -> Result<&[u8], Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        if data.len() > L3_CMD_DATA_SIZE_MAX {
            return Err(Error::RequestExceedsSize);
        }
        let data = [data];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::Ping as u8, &data[..]);
        let res = self.lt_l3_transfer(cmd_raw)?;
        Ok(res.data)
    }

    pub fn get_random_value(
        &mut self,
        n: u8,
    ) -> Result<&[u8], Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let data = [&[n][..]];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::RandomValueGet as u8, &data[..]);
        let res = self.lt_l3_transfer(cmd_raw)?;
        Ok(&res.data[3..])
    }

    pub fn ecc_key_generate(
        &mut self,
        slot: zerocopy::little_endian::U16,
        curve: EccCurve,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let data = [slot.as_bytes(), &[curve as u8]];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::EccKeyGenerate as u8, &data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    pub fn ecc_key_read(
        &mut self,
        slot: zerocopy::little_endian::U16,
    ) -> Result<
        EccKeyReadResponse<'_>,
        Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>,
    > {
        let data = [slot.as_bytes()];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::EccKeyRead as u8, &data[..]);
        let res = self.lt_l3_transfer(cmd_raw)?;
        Ok(EccKeyReadResponse::from_bytes(res.data)?)
    }

    pub fn ecc_key_erase(
        &mut self,
        slot: zerocopy::little_endian::U16,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let data = [slot.as_bytes()];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::EccKeyErase as u8, &data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    pub fn ecdsa_sign(
        &mut self,
        slot: zerocopy::little_endian::U16,
        hash: &[u8; 32],
    ) -> Result<&[u8; 64], Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let padding = [0; 13];
        let data = [slot.as_bytes(), &padding[..], &hash[..]];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::EcDSASign as u8, &data[..]);
        let res = self.lt_l3_transfer(cmd_raw)?;
        let signature = SignResponse::from_bytes(res.data)?.signature;
        debug_assert!(signature.len() == 64);
        Ok(signature
            .try_into()
            // Safety: Expect is safe here because SignResponse verifies the signature length.
            .expect("signature to be 64 bytes long"))
    }

    pub fn eddsa_sign(
        &mut self,
        slot: zerocopy::little_endian::U16,
        msg: &[u8],
    ) -> Result<&[u8; 64], Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        if msg.len() > L3_CMD_DATA_SIZE_MAX {
            return Err(Error::RequestExceedsSize);
        }

        let padding = [0; 13];
        let data = [slot.as_bytes(), &padding[..], msg];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::EdDSASign as u8, &data[..]);
        let res = self.lt_l3_transfer(cmd_raw)?;
        let signature = SignResponse::from_bytes(res.data)?.signature;
        debug_assert!(signature.len() == 64);
        Ok(signature
            .try_into()
            // Safety: Expect is safe here because SignResponse verifies the signature length.
            .expect("signature to be 64 bytes long"))
    }

    /// Initialize a monotonic counter with a specific value.
    ///
    /// # Arguments
    /// * `index` - Counter index (0-15)
    /// * `value` - Initial value (0 to `MCOUNTER_VALUE_MAX`)
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err` if the counter value is out of range
    pub fn mcounter_init(
        &mut self,
        index: MCounterIndex,
        value: u32,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        if value > MCOUNTER_VALUE_MAX {
            return Err(Error::InvalidParameter);
        }

        let index_bytes = (index as u16).to_le_bytes();
        let padding = [0u8; 1];
        let value_bytes = value.to_le_bytes();
        let data = [&index_bytes[..], &padding[..], &value_bytes[..]];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::MCounterInit as u8, &data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    /// Decrement a monotonic counter by 1.
    ///
    /// # Arguments
    /// * `index` - Counter index (0-15)
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err` if the counter is already at 0
    pub fn mcounter_update(
        &mut self,
        index: MCounterIndex,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let index_bytes = (index as u16).to_le_bytes();

        let data = [&index_bytes[..]];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::MCounterUpdate as u8, &data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    /// Read the current value of a monotonic counter.
    ///
    /// # Arguments
    /// * `index` - Counter index (0-15)
    ///
    /// # Returns
    /// * `Ok(value)` - Current counter value
    /// * `Err` if the command's response is too short
    pub fn mcounter_get(
        &mut self,
        index: MCounterIndex,
    ) -> Result<u32, Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let index_bytes = (index as u16).to_le_bytes();

        let data = [&index_bytes[..]];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::MCounterGet as u8, &data[..]);
        let res = self.lt_l3_transfer(cmd_raw)?;

        // Response contains 1 byte result + 4 bytes counter value (little-endian)
        if res.data.len() < 4 {
            return Err(Error::InvalidResponse);
        }

        let value = u32::from_le_bytes([res.data[3], res.data[4], res.data[5], res.data[6]]);

        Ok(value)
    }

    /// Store an ECC key in the given slot.
    pub fn ecc_key_store(
        &mut self,
        slot: zerocopy::little_endian::U16,
        curve: EccCurve,
        key: &[u8; 32],
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        if slot.get() > ECC_SLOT_MAX {
            return Err(Error::InvalidParameter);
        }
        let padding = [0u8; 12];
        let data = [slot.as_bytes(), &[curve as u8], &padding[..], &key[..]];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::EccKeyStore as u8, &data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    /// Write data to an R_MEM_DATA slot.
    pub fn r_mem_data_write(
        &mut self,
        slot: zerocopy::little_endian::U16,
        data: &[u8],
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        if slot.get() > R_MEM_DATA_SLOT_MAX {
            return Err(Error::InvalidParameter);
        }
        if data.is_empty() {
            return Err(Error::InvalidParameter);
        }
        let padding = [0u8; 1];
        let cmd_data = [slot.as_bytes(), &padding[..], data];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::RMemDataWrite as u8, &cmd_data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    /// Read data from an R_MEM_DATA slot.
    pub fn r_mem_data_read(
        &mut self,
        slot: zerocopy::little_endian::U16,
    ) -> Result<&[u8], Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        if slot.get() > R_MEM_DATA_SLOT_MAX {
            return Err(Error::InvalidParameter);
        }
        let data = [slot.as_bytes()];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::RMemDataRead as u8, &data[..]);
        let res = self.lt_l3_transfer(cmd_raw)?;
        // Skip 3 bytes padding
        if res.data.len() < 3 {
            return Err(Error::InvalidResponse);
        }
        Ok(&res.data[3..])
    }

    /// Erase an R_MEM_DATA slot.
    pub fn r_mem_data_erase(
        &mut self,
        slot: zerocopy::little_endian::U16,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        if slot.get() > R_MEM_DATA_SLOT_MAX {
            return Err(Error::InvalidParameter);
        }
        let data = [slot.as_bytes()];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::RMemDataErase as u8, &data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    /// Write a value to an R_CONFIG address.
    pub fn r_config_write(
        &mut self,
        address: zerocopy::little_endian::U16,
        value: u32,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let padding = [0u8; 1];
        let value_bytes = value.to_le_bytes();
        let data = [address.as_bytes(), &padding[..], &value_bytes[..]];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::RConfigWrite as u8, &data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    /// Read a value from an R_CONFIG address.
    pub fn r_config_read(
        &mut self,
        address: zerocopy::little_endian::U16,
    ) -> Result<u32, Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let data = [address.as_bytes()];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::RConfigRead as u8, &data[..]);
        let res = self.lt_l3_transfer(cmd_raw)?;
        // Skip 3 bytes padding, read u32 LE
        if res.data.len() < 7 {
            return Err(Error::InvalidResponse);
        }
        Ok(u32::from_le_bytes([
            res.data[3],
            res.data[4],
            res.data[5],
            res.data[6],
        ]))
    }

    /// Erase R_CONFIG.
    pub fn r_config_erase(
        &mut self,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let data = [];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::RConfigErase as u8, &data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    /// Write a bit to an I_CONFIG address.
    pub fn i_config_write(
        &mut self,
        address: zerocopy::little_endian::U16,
        bit_index: u8,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let data = [address.as_bytes(), &[bit_index][..]];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::IConfigWrite as u8, &data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    /// Read a value from an I_CONFIG address.
    pub fn i_config_read(
        &mut self,
        address: zerocopy::little_endian::U16,
    ) -> Result<u32, Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let data = [address.as_bytes()];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::IConfigRead as u8, &data[..]);
        let res = self.lt_l3_transfer(cmd_raw)?;
        // Skip 3 bytes padding, read u32 LE
        if res.data.len() < 7 {
            return Err(Error::InvalidResponse);
        }
        Ok(u32::from_le_bytes([
            res.data[3],
            res.data[4],
            res.data[5],
            res.data[6],
        ]))
    }

    /// Write a pairing key to the given slot.
    pub fn pairing_key_write(
        &mut self,
        slot: zerocopy::little_endian::U16,
        s_hipub: &[u8; 32],
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        if slot.get() > PAIRING_KEY_SLOT_MAX {
            return Err(Error::InvalidParameter);
        }
        let padding = [0u8; 1];
        let data = [slot.as_bytes(), &padding[..], &s_hipub[..]];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::PairingKeyWrite as u8, &data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    /// Read a pairing key from the given slot.
    pub fn pairing_key_read(
        &mut self,
        slot: zerocopy::little_endian::U16,
    ) -> Result<&[u8; 32], Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        if slot.get() > PAIRING_KEY_SLOT_MAX {
            return Err(Error::InvalidParameter);
        }
        let data = [slot.as_bytes()];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::PairingKeyRead as u8, &data[..]);
        let res = self.lt_l3_transfer(cmd_raw)?;
        // Skip 3 bytes padding, read 32 bytes
        if res.data.len() < 35 {
            return Err(Error::InvalidResponse);
        }
        Ok(res.data[3..35]
            .try_into()
            .expect("pairing key to be 32 bytes"))
    }

    /// Invalidate a pairing key slot.
    pub fn pairing_key_invalidate(
        &mut self,
        slot: zerocopy::little_endian::U16,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        if slot.get() > PAIRING_KEY_SLOT_MAX {
            return Err(Error::InvalidParameter);
        }
        let data = [slot.as_bytes()];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::PairingKeyInvalidate as u8, &data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    /// Perform a MAC-and-destroy operation.
    pub fn mac_and_destroy(
        &mut self,
        slot: zerocopy::little_endian::U16,
        data_in: &[u8; 32],
    ) -> Result<&[u8; 32], Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        if slot.get() > MAC_AND_DESTROY_SLOT_MAX {
            return Err(Error::InvalidParameter);
        }
        let padding = [0u8; 1];
        let data = [slot.as_bytes(), &padding[..], &data_in[..]];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::MacAndDestroy as u8, &data[..]);
        let res = self.lt_l3_transfer(cmd_raw)?;
        // Skip 3 bytes padding, read 32 bytes
        if res.data.len() < 35 {
            return Err(Error::InvalidResponse);
        }
        Ok(res.data[3..35]
            .try_into()
            .expect("mac_and_destroy result to be 32 bytes"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Verifies that L3 command IDs match the TROPIC01 specification.
    /// Reference: libtropic C SDK `src/lt_l3_api_structs.h`
    #[test]
    fn test_l3_command_ids_match_spec() {
        assert_eq!(L3CmdId::Ping as u8, 0x01, "PING command ID mismatch");
        assert_eq!(
            L3CmdId::PairingKeyWrite as u8,
            0x10,
            "PAIRING_KEY_WRITE command ID mismatch"
        );
        assert_eq!(
            L3CmdId::PairingKeyRead as u8,
            0x11,
            "PAIRING_KEY_READ command ID mismatch"
        );
        assert_eq!(
            L3CmdId::PairingKeyInvalidate as u8,
            0x12,
            "PAIRING_KEY_INVALIDATE command ID mismatch"
        );
        assert_eq!(
            L3CmdId::RConfigWrite as u8,
            0x20,
            "R_CONFIG_WRITE command ID mismatch"
        );
        assert_eq!(
            L3CmdId::RConfigRead as u8,
            0x21,
            "R_CONFIG_READ command ID mismatch"
        );
        assert_eq!(
            L3CmdId::RConfigErase as u8,
            0x22,
            "R_CONFIG_ERASE command ID mismatch"
        );
        assert_eq!(
            L3CmdId::IConfigWrite as u8,
            0x30,
            "I_CONFIG_WRITE command ID mismatch"
        );
        assert_eq!(
            L3CmdId::IConfigRead as u8,
            0x31,
            "I_CONFIG_READ command ID mismatch"
        );
        assert_eq!(
            L3CmdId::RMemDataWrite as u8,
            0x40,
            "R_MEM_DATA_WRITE command ID mismatch"
        );
        assert_eq!(
            L3CmdId::RMemDataRead as u8,
            0x41,
            "R_MEM_DATA_READ command ID mismatch"
        );
        assert_eq!(
            L3CmdId::RMemDataErase as u8,
            0x42,
            "R_MEM_DATA_ERASE command ID mismatch"
        );
        assert_eq!(
            L3CmdId::RandomValueGet as u8,
            0x50,
            "RANDOM_VALUE_GET command ID mismatch"
        );
        assert_eq!(
            L3CmdId::EccKeyGenerate as u8,
            0x60,
            "ECC_KEY_GENERATE command ID mismatch"
        );
        assert_eq!(
            L3CmdId::EccKeyStore as u8,
            0x61,
            "ECC_KEY_STORE command ID mismatch"
        );
        assert_eq!(
            L3CmdId::EccKeyRead as u8,
            0x62,
            "ECC_KEY_READ command ID mismatch"
        );
        assert_eq!(
            L3CmdId::EccKeyErase as u8,
            0x63,
            "ECC_KEY_ERASE command ID mismatch"
        );
        assert_eq!(
            L3CmdId::EcDSASign as u8,
            0x70,
            "ECDSA_SIGN command ID mismatch"
        );
        assert_eq!(
            L3CmdId::EdDSASign as u8,
            0x71,
            "EDDSA_SIGN command ID mismatch"
        );
        assert_eq!(
            L3CmdId::MCounterInit as u8,
            0x80,
            "MCOUNTER_INIT command ID mismatch"
        );
        assert_eq!(
            L3CmdId::MCounterUpdate as u8,
            0x81,
            "MCOUNTER_UPDATE command ID mismatch"
        );
        assert_eq!(
            L3CmdId::MCounterGet as u8,
            0x82,
            "MCOUNTER_GET command ID mismatch"
        );
        assert_eq!(
            L3CmdId::MacAndDestroy as u8,
            0x90,
            "MAC_AND_DESTROY command ID mismatch"
        );
    }

    /// Verifies that L3 result status codes match the TROPIC01 specification.
    #[test]
    fn test_l3_result_status_values() {
        assert_eq!(L3ResultStatus::Ok as u8, 0xc3);
        assert_eq!(L3ResultStatus::Fail as u8, 0x3c);
        assert_eq!(L3ResultStatus::Unauthorized as u8, 0x01);
        assert_eq!(L3ResultStatus::InvalidCmd as u8, 0x02);
        assert_eq!(L3ResultStatus::SlotNotEmpty as u8, 0x10);
        assert_eq!(L3ResultStatus::SlotExpired as u8, 0x11);
        assert_eq!(L3ResultStatus::InvalidKey as u8, 0x12);
        assert_eq!(L3ResultStatus::UpdateErr as u8, 0x13);
        assert_eq!(L3ResultStatus::CounterInvalid as u8, 0x14);
        assert_eq!(L3ResultStatus::SlotEmpty as u8, 0x15);
        assert_eq!(L3ResultStatus::SlotInvalid as u8, 0x16);
        assert_eq!(L3ResultStatus::HardwareFail as u8, 0x17);
    }
}
