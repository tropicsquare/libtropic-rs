use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};

pub fn init_aes256_gcm(iv: &[u8; 12], key: &[u8; 32], ad: &[u8]) -> [u8; 16] {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);

    // Encrypt empty plaintext to get only tag
    let payload = Payload { msg: b"", aad: ad };

    let ct = cipher.encrypt(nonce, payload).unwrap();
    let tag = &ct[ct.len() - 16..];

    let mut result = [0u8; 16];
    result.copy_from_slice(tag);
    result
}

pub fn aes256_gcm(iv: &[u8; 12], key: &[u8; 32], msg: &[u8], ad: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);

    // Encrypt empty plaintext to get only tag
    let payload = Payload { msg, aad: ad };

    let ct = cipher.encrypt(nonce, payload).unwrap();
    let tag_slice = &ct[ct.len() - 16..];

    let mut tag = [0u8; 16];
    tag.copy_from_slice(tag_slice);
    (ct, tag)
}

pub fn aes256_gcm_concat(iv: &[u8; 12], key: &[u8; 32], msg: &[u8], ad: &[u8]) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);

    // Encrypt empty plaintext to get only tag
    let payload = Payload { msg, aad: ad };

    let ct = cipher.encrypt(nonce, payload).unwrap();
    ct
}
