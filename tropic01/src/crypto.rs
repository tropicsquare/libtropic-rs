use aes_gcm::Aes256Gcm;
use aes_gcm::Key;
use aes_gcm::KeyInit as _;
use aes_gcm::aead::AeadMutInPlace;
use aes_gcm::aead::arrayvec::ArrayVec;
use hmac::Hmac;
use hmac::Mac;
use sha2::Digest;
use sha2::Sha256;

use crate::Aes256GcmKey;
use crate::L3_FRAME_MAX_SIZE;
use crate::Nonce;

type HmacSha256 = Hmac<Sha256>;

pub trait X25519 {
    type PublicKey: AsRef<[u8]> + Copy + From<[u8; 32]>;
    type StaticSecret;
    type SharedSecret: AsRef<[u8]>;

    fn diffie_hellman(
        &self,
        private_key: &Self::StaticSecret,
        public_key: &Self::PublicKey,
    ) -> Self::SharedSecret;
}

#[cfg(feature = "x25519-dalek")]
#[derive(Clone, Copy, Debug, Default)]
pub struct X25519Dalek;

#[cfg(feature = "x25519-dalek")]
impl X25519 for X25519Dalek {
    type PublicKey = x25519_dalek::PublicKey;
    type SharedSecret = x25519_dalek::SharedSecret;
    type StaticSecret = x25519_dalek::StaticSecret;

    fn diffie_hellman(
        &self,
        private_key: &Self::StaticSecret,
        public_key: &Self::PublicKey,
    ) -> Self::SharedSecret {
        private_key.diffie_hellman(public_key)
    }
}

/// Represents all errors that can happen during encryption and decryption of L3
/// commands and results.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum CryptoError {
    #[display("Decryption failed: {}", _0)]
    Decryption(#[error(not(source))] aes_gcm::Error),
    #[display("Encryption failed: {}", _0)]
    Encryption(#[error(not(source))] aes_gcm::Error),
}

/// Cryptographic key
///
/// This type only exists to ensure [hkdf] only ever received 32 or 33 byte long
/// slices.
#[derive(derive_more::From)]
pub(super) enum CK<'a> {
    CK32(&'a [u8; 32]),
    CK33(&'a [u8; 33]),
}

impl AsRef<[u8]> for CK<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            CK::CK32(bytes) => bytes.as_slice(),
            CK::CK33(bytes) => bytes.as_slice(),
        }
    }
}

/// HMAC Key Derivation Function
///
/// see section 7.4.1 of the datasheet
pub(super) fn hkdf(ck: CK<'_>, input: &[u8]) -> ([u8; 33], [u8; 32]) {
    fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        // Safety: Expect is safe here because `key` is either 32 or 33 bytes long and `new_from_slice` is not panicking on those.
        .expect("key to be 32 bytes");
        mac.update(msg);
        let result = mac.finalize();
        result.into_bytes().into()
    }

    let one = [0x01];
    let tmp = hmac_sha256(ck.as_ref(), input);
    let output_1 = hmac_sha256(&tmp, &one);
    let mut helper: [u8; 33] = [0; 33];
    let (left, right) = helper.split_at_mut(32);
    left.copy_from_slice(&output_1);
    right[0] = 2;
    let output_2 = hmac_sha256(&tmp, &helper);
    helper[32] = 0;
    (helper, output_2)
}

/// See section 7.4.1, figure 14 of the datasheet
pub(super) fn sha256_sequence(
    protocol_name: &[u8],
    shipub: &[u8],
    stpub: &[u8],
    ehpub: &[u8],
    pkey_index: u8,
    etpub: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(protocol_name);
    let hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash);
    hasher.update(shipub);
    let hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash);
    hasher.update(stpub);
    let hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash);
    hasher.update(ehpub);
    let hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash);
    hasher.update([pkey_index]);
    let hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash);
    hasher.update(etpub);
    let hash = hasher.finalize();

    hash.into()
}

pub(super) fn aesgcm_encrypt(
    key: &Aes256GcmKey,
    nonce: &Nonce,
    aad: &[u8],
    buf: &mut ArrayVec<u8, L3_FRAME_MAX_SIZE>,
) -> Result<[u8; 16], CryptoError> {
    let nonce = nonce.as_ref().into();
    let key: &Key<Aes256Gcm> = key.as_ref().into();
    let mut cipher = Aes256Gcm::new(key);

    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, buf)
        .map_err(CryptoError::Encryption)?;
    Ok(tag.into())
}

pub(super) fn aesgcm_decrypt(
    key: &Aes256GcmKey,
    nonce: &Nonce,
    aad: &[u8],
    tag: &[u8],
    buf: &mut [u8],
) -> Result<(), CryptoError> {
    let nonce = nonce.as_ref().into();
    let key: &Key<Aes256Gcm> = key.as_ref().into();
    let mut cipher = Aes256Gcm::new(key);
    let tag = tag.into();
    cipher
        .decrypt_in_place_detached(nonce, aad, buf, tag)
        .map_err(CryptoError::Decryption)
}
