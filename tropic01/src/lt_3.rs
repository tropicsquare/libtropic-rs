use embedded_hal::digital::ErrorType as GpioErrorType;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::ErrorType as SpiErrorType;
use embedded_hal::spi::SpiDevice;
use nom_derive::Nom;
use zerocopy::IntoBytes;
use zerocopy::little_endian::U16;

use crate::Error;
use crate::FromBytes;
use crate::L3_CMD_DATA_SIZE_MAX;
use crate::L3_RES_SIZE_SIZE;
use crate::L3_TAG_SIZE;
use crate::Tropic01;
use crate::crypto::aesgcm_decrypt;
use crate::crypto::aesgcm_encrypt;
use crate::lt_2::l2_receive_encrypted_cmd;
use crate::lt_2::l2_send_encrypted_cmd;

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
    RandomValueGet = 0x50,
    EccKeyRead = 0x62,
    EcDSASign = 0x70,
    EdDSASign = 0x71,
}

/// Represents all kinds of curves the chip supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom)]
#[repr(u8)]
pub enum EccCurve {
    P256 = 0x01,
    Ed25519 = 0x02,
}

impl EccCurve {
    const fn key_len(self) -> usize {
        match self {
            EccCurve::Ed25519 => 32,
            EccCurve::P256 => 64,
        }
    }
}

#[derive(Debug, Nom)]
pub(super) struct L3ResultPacket<'a> {
    #[nom(LittleEndian)]
    _size: u16,
    #[nom(Take = "_size")]
    _ciphertext: &'a [u8],
    _tag: [u8; 16],
}

/// Decrypted result data.
///
/// This is the decrypted content of [L3ResultPacket]s `ciphertext` field.
#[derive(Debug, Nom)]
#[nom(Exact)]
struct L3ResultData<'a> {
    result: L3ResultStatus,
    #[nom(Take = "i.len()")]
    data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom, derive_more::Display, derive_more::Error)]
#[repr(u8)]
enum L3ResultStatus {
    Ok = 0xc3,
    Fail = 0x3c,
    Unauthorized = 0x01,
    InvalidCmd = 0x02,
    InvalidKey = 0x12,
}

/// Represents all kinds of origins the chip supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom)]
#[repr(u8)]
pub enum EccOrigin {
    /// Key originated from the [Tropic01::ecc_key_generate] method.
    KeyGenerate = 0x01,
    /// Key originated from the [Tropic01::ecc_key_read] method.
    KeyStore = 0x02,
}

#[derive(Debug, Clone, Nom)]
pub struct EccKeyReadResponse<'a> {
    curve: EccCurve,
    origin: EccOrigin,
    /// The public key. For P-256 curves, this is the uncompressed x + y
    /// coordinates.
    #[nom(Take = "curve.key_len()", SkipBefore(13))]
    pub_key: &'a [u8],
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

#[derive(Debug, Clone, Nom)]
struct SignResponse<'a> {
    #[nom(SkipBefore(15), Take(64))]
    signature: &'a [u8],
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
            L3ResultStatus::InvalidCmd => {
                return Err(Error::InvalidL3Cmd);
            },
            L3ResultStatus::InvalidKey => return Err(Error::InvalidKey),
            L3ResultStatus::Unauthorized => return Err(Error::Unauthorized),
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
        slot: zerocopy::big_endian::U16,
        curve: EccCurve,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let data = [slot.as_bytes(), &[curve as u8]];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::EcDSASign as u8, &data[..]);
        self.lt_l3_transfer(cmd_raw)?;
        Ok(())
    }

    pub fn ecc_key_read(
        &mut self,
        slot: zerocopy::big_endian::U16,
    ) -> Result<
        EccKeyReadResponse<'_>,
        Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>,
    > {
        let data = [slot.as_bytes()];
        let cmd_raw = DecryptedL3CommandPacket::new(L3CmdId::EccKeyRead as u8, &data[..]);
        let res = self.lt_l3_transfer(cmd_raw)?;
        Ok(EccKeyReadResponse::from_bytes(res.data)?)
    }

    pub fn ecdsa_sign(
        &mut self,
        slot: zerocopy::big_endian::U16,
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
        slot: zerocopy::big_endian::U16,
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
}
