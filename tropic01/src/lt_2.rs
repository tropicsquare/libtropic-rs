use core::iter::repeat_n;

use aes_gcm::aead::arrayvec::ArrayVec;
use embedded_hal::digital::ErrorType as GpioErrorType;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::ErrorType as SpiErrorType;
use embedded_hal::spi::SpiDevice;
use nom_derive::Nom;
use zerocopy::BE;
use zerocopy::IntoBytes;
use zerocopy::U16;
use zerocopy::Unaligned;

use super::Error;
use super::Tropic01;
use crate::Aes256GcmKey;
use crate::FromBytes;
use crate::L2_CHUNK_MAX_DATA_SIZE;
use crate::L2_CMD_REQ_LEN;
use crate::L3_CMD_DATA_SIZE_MAX;
use crate::L3_CMD_SIZE_SIZE;
use crate::L3_FRAME_MAX_SIZE;
use crate::L3_RES_SIZE_SIZE;
use crate::L3_TAG_SIZE;
use crate::Nonce;
use crate::crc16::Crc16;
use crate::crypto::CryptoError;
use crate::crypto::X25519;
use crate::crypto::aesgcm_decrypt;
use crate::crypto::hkdf;
use crate::crypto::sha256_sequence;
use crate::lt_1::l1_delay_ns;
use crate::lt_1::l1_read;
use crate::lt_1::l1_write;
use crate::lt_3::EncryptedL3CommandPacket;
use crate::lt_3::L3ResultPacket;

const L2_GET_INFO_REQ_CERT_SIZE: usize = 512;
/// Protocol Name
/// See section 7.4.1 of the datasheet, section `Protocol Name`.
const PROTOCOL_NAME: &[u8; 32] = b"Noise_KK1_25519_AESGCM_SHA256\x00\x00\x00";

#[derive(Debug)]
#[repr(u8)]
enum L2RequestId {
    EncryptedCmdReq = 0x04,
    GetInfo = 0x01,
    GetLog = 0xa2,
    HandshakeReq = 0x02,
    ResendReq = 0x10,
    SleepReq = 0x20,
    StartupReq = 0xb3,
}

/// Represents all possible response status codes the chip may return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom, derive_more::Display, derive_more::Error)]
#[repr(u8)]
pub enum ResponseStatus {
    ReqOk = 0x01,
    ResOk = 0x02,
    ReqCont = 0x03,
    ResCont = 0x04,
    #[display("The l2 request frame is disabled and can't be executed")]
    RespDisabled = 0x78,
    #[display(
        "Secure channel handshake failed (e.g. pairing key slot from `pkey_index`field has an \
         invalid x25519 public key"
    )]
    HskErr = 0x79,
    #[display(
        "Chip is not in secure channel mode and host has sent L3 command. Request is ignored"
    )]
    NoSession = 0x7a,
    #[display(
        "Invalid L3 command packet authentication tag. Request is ignored, chip invalidates the \
         current secure channel session and moves to `idle` mode"
    )]
    TagErr = 0x7b,
    #[display("Chip received invalid CRC-16 checksum, request is ignored")]
    CrcErr = 0x7c,
    #[display("Unknown L2 request frame is received (invalid REQ_ID)")]
    UnknownReq = 0x7e,
    #[display("Generic error (cannot be classified under other status codes)")]
    GenErr = 0x7f,
    #[display("No L2 response frame available")]
    NoResp = 0xff,
}
#[derive(Clone, Debug, IntoBytes, Unaligned)]
#[repr(C)]
pub(super) struct L2RequestFrame<'a> {
    id: u8,
    len: u8,
    data: &'a [&'a [u8]],
    crc: U16<BE>,
}

impl<'a> L2RequestFrame<'a> {
    pub fn new(id: u8, data: &'a [&'a [u8]]) -> Self {
        assert!(data.len() <= u8::MAX as usize);
        let len = data.iter().map(|d| d.len()).sum::<usize>() as u8;

        let crc = Self::crc(id, len, data);
        Self { id, len, data, crc }
    }

    fn crc(id: u8, len: u8, data: &'a [&'a [u8]]) -> U16<BE> {
        let mut crc = Crc16::new();
        crc.update(&[id]);
        crc.update(&[len]);
        for d in data {
            crc.update(d);
        }
        crc.get().into()
    }
}

#[derive(Debug, Nom)]
struct L2ResponseFrame<'a> {
    _chip_status: u8,
    resp_status: ResponseStatus,
    len: u8,
    #[nom(Take = "len")]
    resp_data: &'a [u8],
    #[nom(BigEndian)]
    crc: u16,
}

impl<'a> L2ResponseFrame<'a> {
    pub const fn resp_data(&self) -> &'a [u8] {
        self.resp_data
    }

    pub fn check_frame(&self) -> bool {
        let mut crc16 = Crc16::new();
        crc16.update(&[self.resp_status as u8]);
        crc16.update(&[self.len]);
        crc16.update(self.resp_data);
        crc16.get() == self.crc
    }
}

#[derive(Debug)]
#[repr(u8)]
enum InfoReq {
    X509Certificate = 0x00,
    ChipId = 0x01,
    _RiscvFwVersion = 0x02,
    _SpectFwVersion = 0x04,
    _FwBank = 0xb0,
}

#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum PublicKeyError {
    #[display("Could not find public key in X509 certificate")]
    PublicKeyNotFound,
}

/// The x509 certificate of the chip containing the public key.
#[derive(Debug)]
pub struct X509Certificate<'a> {
    data: &'a [u8; L2_GET_INFO_REQ_CERT_SIZE],
}

impl<'a> X509Certificate<'a> {
    const fn new(data: &'a [u8; L2_GET_INFO_REQ_CERT_SIZE]) -> Self {
        Self { data }
    }

    /// Return the public key
    pub fn public_key(&self) -> Result<&[u8; 32], PublicKeyError> {
        // TODO consider using appropriate ASN.1 DER parsing for this
        let seq = [0x65, 0x6e, 0x03, 0x21];
        let len = seq.len();
        let pos = self
            .data
            .windows(len)
            .position(|window| window == seq)
            .ok_or(PublicKeyError::PublicKeyNotFound)?;
        let start = pos + len + 1; // +1 to remove leading '0' for uncompressed public key
        self.data[start..start + 32]
            .try_into()
            .map_err(|_| PublicKeyError::PublicKeyNotFound)
    }
}

/// Represents the types of startup requests the chip supports.
#[derive(Debug)]
#[repr(u8)]
pub enum StartupReq {
    Reboot = 0x01,
    MaintenanceReboot = 0x03,
}

/// Represents all kinds of sleep requests the chip supports.
#[derive(Debug)]
#[repr(u8)]
pub enum SleepReq {
    Sleep = 0x05,
    DeepSleep = 0x0a,
}

#[derive(Debug, Nom)]
struct HandShakeResponse<'a> {
    #[nom(Take = "32")]
    etpub: &'a [u8],
    #[nom(Take = "16")]
    ttauth: &'a [u8],
}

impl<SPI: SpiDevice, CS: OutputPin> Tropic01<SPI, CS> {
    fn get_info_req(
        &mut self,
        req: InfoReq,
        block: u8,
    ) -> Result<
        L2ResponseFrame<'_>,
        Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>,
    > {
        get_info_req(req, block, &mut self.l2_buf, &mut self.spi, &mut self.cs)
    }

    pub fn get_info_cert(
        &mut self,
    ) -> Result<
        X509Certificate<'_>,
        Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>,
    > {
        self.l3_buf.clear();
        self.l3_buf.extend(repeat_n(0, L2_GET_INFO_REQ_CERT_SIZE));
        for (i, chunk) in self.l3_buf.chunks_mut(128).enumerate() {
            let res = get_info_req(
                InfoReq::X509Certificate,
                i as u8,
                &mut self.l2_buf,
                &mut self.spi,
                &mut self.cs,
            )?;
            chunk[..res.resp_data.len()].copy_from_slice(res.resp_data);
        }
        Ok(X509Certificate::new(
            self.l3_buf
                .as_slice()
                .try_into()
                // Safety: Expect is safe since `l3_buf` has L2_GET_INFO_REQ_CERT_SIZE items
                .expect("l3 buffer length to match certificate length"),
        ))
    }

    pub fn get_info_chip_id(
        &mut self,
    ) -> Result<&[u8], Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let res = self.get_info_req(InfoReq::ChipId, 0)?;
        Ok(res.resp_data())
    }

    pub fn get_log_req(
        &mut self,
    ) -> Result<&[u8], Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        // TODO impl chunked response (response can be upto 255 bytes, exceeding normal
        // l2 response)
        let data = [];
        let frame = L2RequestFrame::new(L2RequestId::GetLog as u8, &data);
        let res = l2_transfer(frame, &mut self.l2_buf, &mut self.spi, &mut self.cs)?;
        Ok(res.resp_data())
    }

    pub fn sleep_req(
        &mut self,
        req: SleepReq,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let data = [&[req as u8][..]];
        let frame = L2RequestFrame::new(L2RequestId::SleepReq as u8, &data[..]);
        l2_transfer(frame, &mut self.l2_buf, &mut self.spi, &mut self.cs)?;
        Ok(())
    }

    pub fn startup_req(
        &mut self,
        req: StartupReq,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let data = [&[req as u8][..]];
        let frame = L2RequestFrame::new(L2RequestId::StartupReq as u8, &data[..]);
        l2_transfer(frame, &mut self.l2_buf, &mut self.spi, &mut self.cs)?;
        Ok(())
    }

    /// Start a secure session
    ///
    /// Arguments:
    /// - shipub: Secret host public key corresponding to slot `pkey_index`
    /// - shipriv: Secret host private key corresponding to slot `pkey_index`
    /// - ehpub: Ephemeral public key
    /// - ehpriv: Ephemeral private key
    pub fn session_start<X: X25519>(
        &mut self,
        x25519: &X,
        shipub: X::PublicKey,
        shipriv: X::StaticSecret,
        ehpub: X::PublicKey,
        ehpriv: X::StaticSecret,
        pkey_index: u8,
    ) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
        let cert = self.get_info_cert()?;
        let stpub = *cert.public_key().map_err(|_| Error::InvalidPublicKey)?;

        let hdshk = self.handshake_req::<X>(ehpub, 0)?;
        let etpub: [u8; 32] = hdshk
            .etpub
            .try_into()
            // Safety: This is safe since the field is verified in HandShakeResponse
            .expect("response to contain public key (32 bytes)");
        let ttauth: [u8; 16] = hdshk
            .ttauth
            .try_into()
            // Safety: This is safe since the field is verified in HandShakeResponse
            .expect("response to contain authentication tag (16 bytes)");

        let (kcmd, kres) = process_handshake(
            x25519,
            etpub.into(),
            ehpub,
            ehpriv,
            shipub,
            shipriv,
            stpub.into(),
            ttauth,
            pkey_index,
        )
        .map_err(|_| Error::HandshakeFailed)?;

        self.session = Some(super::Session::new(kcmd, kres));

        Ok(())
    }

    fn handshake_req<X: X25519>(
        &mut self,
        ehpub: X::PublicKey,
        pkey_index: u8,
    ) -> Result<
        HandShakeResponse<'_>,
        Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>,
    > {
        let data = [ehpub.as_ref(), &[pkey_index][..]];
        let frame = L2RequestFrame::new(L2RequestId::HandshakeReq as u8, &data[..]);
        let res = l2_transfer(frame, &mut self.l2_buf, &mut self.spi, &mut self.cs)?;

        Ok(HandShakeResponse::from_bytes(res.resp_data)?)
    }
}

/// Write req into l2_buf and send to chip, then read result via GetRequest
/// command.
fn l2_transfer<'a, SPI: SpiDevice, CS: OutputPin>(
    req: L2RequestFrame<'_>,
    l2_buf: &'a mut [u8],
    spi: &'a mut SPI,
    cs: &'a mut Option<CS>,
) -> Result<L2ResponseFrame<'a>, Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>>
{
    l2_transfer_helper(Some(req), l2_buf, spi, cs)
}

/// If req is None, the caller needs to fill l2_buf with the request before
/// calling this.
fn l2_transfer_helper<'a, SPI: SpiDevice, CS: OutputPin>(
    mut req: Option<L2RequestFrame<'_>>,
    l2_buf: &'a mut [u8],
    spi: &'a mut SPI,
    cs: &'a mut Option<CS>,
) -> Result<L2ResponseFrame<'a>, Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>>
{
    for _ in 0..4 {
        if let Some(req) = req.as_ref() {
            l2_buf.fill(0);
            l2_buf[0] = req.id;
            l2_buf[1] = req.len;
            let mut last_n = 2;
            for data in req.data {
                l2_buf[last_n..last_n + data.len()].copy_from_slice(data);
                last_n += data.len();
            }
            l2_buf[last_n..last_n + 2].copy_from_slice(req.crc.as_bytes());
        }
        l1_write(l2_buf, spi, cs)?;
        l2_buf.fill(0);
        l1_read(l2_buf, spi, cs)?;
        let res = L2ResponseFrame::from_bytes(l2_buf)?;

        if !res.check_frame() {
            return Err(Error::InvalidCRC);
        }

        match res.resp_status {
            ResponseStatus::NoSession => return Err(Error::NoSession),
            ResponseStatus::GenErr => {
                // Retry but ask chip to resend the last response frame.
                req.replace(L2RequestFrame::new(L2RequestId::ResendReq as u8, &[]));
            },
            ResponseStatus::CrcErr => {
                // This may happen for commands immediately issued after a reboot of the
                // chip, in which case the chip will appear ready but
                // respond with CRC errors. If this happens, wait
                // and retry by resending the original request.
                l1_delay_ns(spi, cs, 25_000_000)?;
            },
            ResponseStatus::ReqOk | ResponseStatus::ReqCont => {
                return Ok(L2ResponseFrame::from_bytes(l2_buf)?);
            },
            ResponseStatus::ResOk | ResponseStatus::ResCont => {
                return Err(Error::UnexpectedResponseStatus);
            },
            err => return Err(Error::L2ResponseError(err)),
        }
    }
    Err(Error::InvalidL2Response)
}

pub(super) fn l2_send_encrypted_cmd<'a, SPI: SpiDevice, CS: OutputPin>(
    req: EncryptedL3CommandPacket<'_>,
    l2_buf: &'a mut [u8],
    spi: &'a mut SPI,
    cs: &'a mut Option<CS>,
) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
    let cmd_size = usize::from(req.cmd_size());
    // Number of chunks to be send
    let chunk_num = (L3_CMD_SIZE_SIZE + cmd_size + L3_TAG_SIZE)
        .checked_div(L2_CHUNK_MAX_DATA_SIZE)
        // Safety: Expect is safe here since L2_CHUNK_MAX_DATA_SIZE > 0
        .expect("L2_CHUNK_MAX_DATA_SIZE not to equal 0")
        + 1;
    let chunk_last_len = (L3_RES_SIZE_SIZE + cmd_size + L3_TAG_SIZE)
        .checked_rem(L2_CHUNK_MAX_DATA_SIZE)
        // Safety: Expect is safe here since L2_CHUNK_MAX_DATA_SIZE > 0
        .expect("L2_CHUNK_MAX_DATA_SIZE not to equal 0");

    let cmd_size = req.cmd_size();
    let cmd_size = cmd_size.as_bytes();
    let tag = req.tag();
    let tag = tag.as_slice();
    let mut iter = cmd_size.iter().chain(req.data().iter()).chain(tag).copied();

    // The core::slice::Chunks iterator iterator is only available for slices,
    // therefore chunking is done manually here. Since we can't get slices of the
    // encrypted L3 command packet, items of a chunk are copied to l2_buf directly
    // and the CRC is calculated on the contents of l2_buf.
    for i in 0..chunk_num {
        let n_in_chunk = if i == (chunk_num - 1) {
            chunk_last_len
        } else {
            L2_CHUNK_MAX_DATA_SIZE
        };
        l2_buf.fill(0);
        l2_buf[0] = L2RequestId::EncryptedCmdReq as u8;
        l2_buf[1] = n_in_chunk as u8;
        for n in 0..n_in_chunk {
            l2_buf[n + 2] = iter.next()
            // Safety: Expect is safe here since the for-loops will not draw more items than are in `iter`.
            .expect("item to be present");
        }

        // Since L2RequestFrame is not used here, CRC needs to be calculated manually
        // and written after the remaining data in l2_buf.
        let mut crc = Crc16::new();
        let eod = 2 + n_in_chunk;
        crc.update(&l2_buf[..eod]);
        let crc = crc.get().to_be_bytes();
        l2_buf[eod..eod + 2].copy_from_slice(&crc[..]);

        // TODO original driver uses l1_write and l1_read here without retries.
        let _ = l2_transfer_helper(None, l2_buf, spi, cs)?;
    }
    Ok(())
}

pub(super) fn l2_receive_encrypted_cmd<'a, SPI: SpiDevice, CS: OutputPin>(
    l2_buf: &'a mut [u8],
    l3_buf: &'a mut ArrayVec<u8, { L3_FRAME_MAX_SIZE }>,
    spi: &'a mut SPI,
    cs: &'a mut Option<CS>,
) -> Result<L3ResultPacket<'a>, Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
    l3_buf.clear();
    let mut i = 0;
    while i <= L3_CMD_DATA_SIZE_MAX.saturating_div(L2_CMD_REQ_LEN) {
        l1_read(l2_buf, spi, cs)?;
        let res = L2ResponseFrame::from_bytes(l2_buf)?;
        if !res.check_frame() {
            return Err(Error::InvalidL2Response);
        }
        l3_buf
            .try_extend_from_slice(res.resp_data())
            .map_err(|_| Error::L3ResponseBufferOverflow)?;
        match res.resp_status {
            ResponseStatus::ResCont => {
                i += 1;
            },
            ResponseStatus::ResOk => {
                return Ok(L3ResultPacket::from_bytes(l3_buf)?);
            },
            _ => return Err(Error::L3CmdFailed),
        }
    }
    Err(Error::L3CmdFailed)
}

fn get_info_req<'a, SPI: SpiDevice, CS: OutputPin>(
    req: InfoReq,
    block: u8,
    l2_buf: &'a mut [u8],
    spi: &'a mut SPI,
    cs: &'a mut Option<CS>,
) -> Result<L2ResponseFrame<'a>, Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>>
{
    let data = [&[req as u8][..], &[block][..]];
    let frame = L2RequestFrame::new(L2RequestId::GetInfo as u8, &data[..]);

    l2_transfer(frame, l2_buf, spi, cs)
}

#[expect(clippy::too_many_arguments)]
fn process_handshake<X: X25519>(
    x25519: &X,
    etpub: X::PublicKey,
    ehpub: X::PublicKey,
    ehpriv: X::StaticSecret,
    shipub: X::PublicKey,
    shipriv: X::StaticSecret,
    stpub: X::PublicKey,
    ttauth: [u8; L3_TAG_SIZE],
    pkey_index: u8,
) -> Result<(Aes256GcmKey, Aes256GcmKey), CryptoError> {
    let hash = sha256_sequence(
        PROTOCOL_NAME,
        shipub.as_ref(),
        stpub.as_ref(),
        ehpub.as_ref(),
        pkey_index,
        etpub.as_ref(),
    );

    // ck = HKDF (ck, X25519(EHPRIV, ETPUB), 1)
    let shared_secret = x25519.diffie_hellman(&ehpriv, &etpub);
    let (output_1, _output_2) = hkdf(PROTOCOL_NAME.into(), shared_secret.as_ref());

    // ck = HKDF (ck, X25519(SHiPRIV, ETPUB), 1)
    let shared_secret = x25519.diffie_hellman(&shipriv, &etpub);
    let (output_1, _output_2) = hkdf((&output_1).into(), shared_secret.as_ref());

    // ck, kAUTH = HKDF (ck, X25519(EHPRIV, STPUB), 2)
    let shared_secret = x25519.diffie_hellman(&ehpriv, &stpub);
    let (output_1, kauth) = hkdf((&output_1).into(), shared_secret.as_ref());

    let (kcmd, kres) = hkdf((&output_1).into(), b"");

    let mut hash_buf: [u8; 0] = *b"";

    // The hash is passed as aad, and an empty message is passed as the to be
    // decrypted message
    aesgcm_decrypt(
        &Aes256GcmKey(kauth),
        &Nonce::default(),
        &hash,
        &ttauth,
        &mut hash_buf,
    )?;

    let mut kcmd_out: [u8; 32] = [0; 32];
    kcmd_out.copy_from_slice(&kcmd[0..32]);

    Ok((Aes256GcmKey(kcmd_out), Aes256GcmKey(kres)))
}

#[cfg(test)]
mod test {
    use x25519_dalek::PublicKey;
    use x25519_dalek::StaticSecret;
    use zerocopy::big_endian::U16;

    use crate::Aes256GcmKey;
    use crate::FromBytes;
    use crate::Nonce;
    use crate::crypto::X25519Dalek;
    use crate::crypto::aesgcm_decrypt;
    use crate::crypto::hkdf;
    use crate::crypto::sha256_sequence;
    use crate::keys::SH0PRIV;
    use crate::keys::SH0PUB;
    use crate::lt_2::L2RequestFrame;
    use crate::lt_2::L2ResponseFrame;
    use crate::lt_2::PROTOCOL_NAME;
    use crate::lt_2::process_handshake;

    #[test]
    fn test_l2_req_frame_correct() {
        let data = [&[0x01u8, 0x01u8][..]];
        let req = L2RequestFrame::new(0x01, &data[..]);

        assert_eq!(0x01, req.id);
        assert_eq!(0x02, req.len);
        assert_eq!(&data, req.data);

        assert_eq!(U16::from_bytes([0x2e, 0x12]), req.crc);
    }
    #[test]
    fn test_l2_res_frame_correct() {
        let data = [0x01, 0x02, 0x01, 0x01, 0x2e, 0x12];
        let frame = L2ResponseFrame::from_bytes(&data).unwrap();
        assert_eq!(frame.crc, 0x2e12);
    }

    #[test]
    fn session_start_works() {
        let pkey_index = 0;
        let expected_hash: [u8; 32] = [
            0x9d, 0xdc, 0x24, 0x77, 0x48, 0x6f, 0x8a, 0x9a, 0x2, 0x27, 0xa8, 0x4b, 0xe9, 0xb9,
            0x5e, 0x29, 0x30, 0xad, 0x4f, 0x68, 0x48, 0x1e, 0x8c, 0xa6, 0x90, 0x34, 0x7e, 0xab,
            0xbe, 0xec, 0xfd, 0xc8,
        ];
        let ehpub: [u8; 32] = [
            0x42, 0xd2, 0x27, 0x0, 0x0, 0xb9, 0xea, 0x70, 0xb6, 0xb8, 0x7c, 0xf9, 0x61, 0x6, 0xca,
            0x3f, 0x3a, 0xd7, 0xe1, 0x2, 0xcc, 0xc9, 0x41, 0xdb, 0xb9, 0x91, 0x72, 0x8c, 0xa0,
            0x89, 0xcd, 0x56,
        ];
        let ehpriv: [u8; 32] = [
            0x18, 0x70, 0x0, 0x0, 0xb3, 0x8, 0x0, 0x0, 0xc9, 0xad, 0x0, 0x0, 0x29, 0xb9, 0x0, 0x0,
            0x14, 0x6e, 0x0, 0x0, 0x2c, 0xde, 0x0, 0x0, 0xbd, 0x45, 0x0, 0x0, 0x1f, 0x56, 0x0, 0x0,
        ];
        let etpub: [u8; 32] = [
            0x16, 0xf6, 0xa5, 0xf9, 0x76, 0x11, 0x2b, 0xe5, 0xfe, 0x7b, 0x2c, 0x7, 0xfc, 0xa8,
            0x6c, 0x43, 0xb1, 0xc9, 0x31, 0x51, 0xde, 0xce, 0x75, 0x5b, 0x79, 0x38, 0xe8, 0xde,
            0x17, 0x7b, 0x61, 0x3c,
        ];
        let shipriv = StaticSecret::from(SH0PRIV);
        let shipub = PublicKey::from(SH0PUB);
        let stpub: [u8; 32] = [
            0x7c, 0xcc, 0x66, 0x64, 0x90, 0x36, 0xcd, 0x66, 0xa5, 0x52, 0xef, 0x2d, 0x19, 0x7a,
            0xae, 0xf5, 0xc7, 0x4e, 0x70, 0x4f, 0xf7, 0x1b, 0x8d, 0xea, 0x70, 0xb, 0xec, 0x65,
            0xca, 0xf9, 0xdf, 0x1f,
        ];

        let ttauth: [u8; 16] = [
            0xe4, 0x1d, 0xaa, 0x79, 0x39, 0xde, 0x59, 0xe3, 0x77, 0x4c, 0x29, 0x3d, 0x1c, 0x86,
            0xa3, 0x91,
        ];
        let expected_output1_1: [u8; 33] = [
            0xc5, 0x18, 0xd2, 0xe6, 0xfa, 0xad, 0xf3, 0x60, 0x3f, 0x9a, 0x48, 0x50, 0x10, 0xe9,
            0x83, 0x81, 0xe7, 0xba, 0xc4, 0x9f, 0x65, 0x6e, 0xb1, 0x3c, 0xbc, 0x44, 0xd1, 0x3d,
            0x7b, 0xb2, 0x3c, 0xee, 0x0,
        ];
        let expected_output1_2: [u8; 32] = [
            0x3, 0x5d, 0x28, 0xc5, 0x2c, 0xe1, 0x1f, 0xc6, 0x4d, 0x20, 0x5d, 0xab, 0xd4, 0x49,
            0x52, 0x9f, 0x38, 0x10, 0xeb, 0xf0, 0xc6, 0x16, 0xd2, 0x52, 0xf0, 0x9a, 0x47, 0x6f,
            0xfe, 0xc2, 0xd3, 0x43,
        ];
        let expected_shared_secret1: [u8; 32] = [
            0x2f, 0xba, 0x30, 0x47, 0x5a, 0xfc, 0xce, 0x60, 0xdc, 0x40, 0x27, 0x8b, 0xb7, 0xbc,
            0xe8, 0x94, 0x9a, 0x2f, 0x8f, 0x4b, 0x8a, 0xb8, 0x97, 0xf4, 0x64, 0x40, 0xe1, 0x6b,
            0xbb, 0xb, 0xde, 0x1b,
        ];
        let expected_output2_1: [u8; 33] = [
            0x96, 0xa0, 0xdd, 0xdd, 0xcf, 0xdb, 0xf5, 0x34, 0x16, 0xc4, 0xfc, 0x27, 0x1f, 0x9b,
            0xed, 0x55, 0xb0, 0x96, 0x1a, 0x3, 0x57, 0x77, 0xc7, 0xa4, 0x99, 0x5b, 0x5f, 0xfc, 0x8,
            0x7f, 0x89, 0x25, 0x0,
        ];
        let expected_output2_2: [u8; 32] = [
            0xb3, 0x7c, 0x3e, 0x41, 0x8f, 0xe3, 0x61, 0x47, 0xf9, 0xa2, 0x97, 0x90, 0x11, 0xe9,
            0x33, 0x21, 0x92, 0x15, 0x77, 0x51, 0x8c, 0xb, 0x12, 0xfe, 0xba, 0x43, 0xa1, 0xb6,
            0x33, 0xf, 0x55, 0x26,
        ];
        let expected_shared_secret2: [u8; 32] = [
            0xd7, 0x72, 0xd0, 0x47, 0x11, 0xb5, 0x20, 0xf0, 0x73, 0xf, 0x5f, 0x77, 0x2e, 0x99,
            0xce, 0x42, 0x3b, 0x2e, 0x94, 0x72, 0xd0, 0xb7, 0x93, 0x3b, 0xdf, 0x35, 0x51, 0x49,
            0x5b, 0xde, 0x16, 0x34,
        ];

        let expected_shared_secret3: [u8; 32] = [
            0x97, 0x92, 0xd7, 0x72, 0x93, 0xd6, 0x16, 0x0, 0x42, 0x9a, 0xc5, 0xaf, 0xa0, 0xfb,
            0x81, 0xa7, 0x64, 0x1e, 0x68, 0xd1, 0x37, 0x9a, 0xfc, 0x52, 0x4, 0x8c, 0x66, 0x2c,
            0xf5, 0xe1, 0xd6, 0x75,
        ];
        let expected_output3_1: [u8; 33] = [
            0x54, 0xe8, 0x99, 0x34, 0x6, 0x30, 0xdd, 0x0, 0x10, 0xa3, 0xee, 0x3e, 0xb6, 0x8b, 0xe2,
            0x6d, 0x67, 0x1d, 0xc0, 0x64, 0xa0, 0x13, 0xf4, 0xae, 0x11, 0xaf, 0x93, 0x7, 0x20, 0x8,
            0x4c, 0x59, 0x0,
        ];
        let expected_kauth3: [u8; 32] = [
            0xbf, 0xb0, 0x22, 0xba, 0x66, 0x3c, 0x3, 0xd6, 0x13, 0x5b, 0xd4, 0x91, 0x60, 0xd8,
            0x2f, 0x65, 0x90, 0xe7, 0xfc, 0xa9, 0xff, 0xb8, 0x26, 0xbd, 0x7, 0xa0, 0x40, 0xa7, 0x4,
            0xf7, 0x56, 0xe6,
        ];
        let expected_kcmd4: [u8; 32] = [
            0x21, 0x52, 0x5b, 0xc7, 0xbd, 0xf0, 0x34, 0x50, 0x87, 0xa9, 0xb, 0x7e, 0xed, 0x2b,
            0x3b, 0xf, 0x8b, 0x42, 0x7d, 0xfe, 0xd4, 0x21, 0x78, 0xe7, 0x4a, 0xc0, 0xcd, 0x94,
            0xc8, 0x6a, 0x41, 0xc6,
        ];
        let expected_kres4: [u8; 32] = [
            0xac, 0x7b, 0xf1, 0xa5, 0x1a, 0x65, 0x53, 0xb8, 0xa4, 0xd3, 0x75, 0x7, 0x4a, 0xa5,
            0x86, 0x48, 0x3, 0x1a, 0xcb, 0x70, 0xb2, 0xf5, 0x44, 0xf8, 0x4f, 0x58, 0xc1, 0x14,
            0xd4, 0xa9, 0x1d, 0x20,
        ];

        let etpub = PublicKey::from(etpub);
        let ehpriv = StaticSecret::from(ehpriv);
        let stpub = PublicKey::from(stpub);

        let hash = sha256_sequence(
            PROTOCOL_NAME,
            shipub.as_bytes(),
            stpub.as_bytes(),
            &ehpub,
            pkey_index,
            etpub.as_bytes(),
        );
        assert_eq!(hash, expected_hash);

        let shared_secret = ehpriv.diffie_hellman(&etpub);
        let (output_1, output_2) = hkdf(PROTOCOL_NAME.into(), shared_secret.as_bytes());

        assert_eq!(&expected_shared_secret1, shared_secret.as_bytes());
        assert_eq!(output_1, expected_output1_1);
        assert_eq!(output_2, expected_output1_2);

        // ck = HKDF (ck, X25519(SHiPRIV, ETPUB), 1)
        let shared_secret = shipriv.diffie_hellman(&etpub);
        let (output_1, output_2) = hkdf((&output_1).into(), shared_secret.as_bytes());

        assert_eq!(&expected_shared_secret2, shared_secret.as_bytes());
        assert_eq!(output_1, expected_output2_1);
        assert_eq!(output_2, expected_output2_2);

        // ck, kAUTH = HKDF (ck, X25519(EHPRIV, STPUB), 2)
        let shared_secret = ehpriv.diffie_hellman(&stpub);
        let (output_1, kauth) = hkdf((&output_1).into(), shared_secret.as_bytes());

        assert_eq!(&expected_shared_secret3, shared_secret.as_bytes());
        assert_eq!(output_1, expected_output3_1);
        assert_eq!(kauth, expected_kauth3);

        let (kcmd, kres) = hkdf((&output_1).into(), b"");
        assert_eq!(kcmd[..32], expected_kcmd4);
        assert_eq!(kres, expected_kres4);

        let mut hash_buf: [u8; 0] = *b"";

        aesgcm_decrypt(
            &Aes256GcmKey(kauth),
            &Nonce::default(),
            &hash,
            &ttauth,
            &mut hash_buf,
        )
        .unwrap();

        let (kcmd_test, kres_test) = process_handshake(
            &X25519Dalek,
            etpub,
            ehpub.into(),
            ehpriv,
            shipub,
            shipriv,
            stpub,
            ttauth,
            pkey_index,
        )
        .unwrap();

        assert_eq!(&kcmd[..32], kcmd_test.as_ref());
        assert_eq!(&kres, kres_test.as_ref());
    }
}
