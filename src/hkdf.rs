use sha2::{Digest, Sha256};

const B: usize = 64;
const L: usize = 32; // SHA256_DIGEST_SIZE
const I_PAD: u8 = 0x36;
const O_PAD: u8 = 0x5C;

pub fn hmac_sha256(data: &[u8], key: &[u8]) -> [u8; L] {
    assert!(key.len() <= B);

    let mut key_block = [0u8; B];
    if key.len() > B {
        let mut hasher = Sha256::new();
        hasher.update(key);
        key_block[..L].copy_from_slice(&hasher.finalize());
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut kx = [0u8; B];
    for i in 0..B {
        kx[i] = key_block[i] ^ I_PAD;
    }

    let mut inner = Sha256::new();
    inner.update(&kx);
    inner.update(data);
    let inner_result = inner.finalize();

    for i in 0..B {
        kx[i] = key_block[i] ^ O_PAD;
    }

    let mut outer = Sha256::new();
    outer.update(&kx);
    outer.update(&inner_result);
    let result = outer.finalize();

    let mut out = [0u8; L];
    out.copy_from_slice(&result);
    out
}

pub fn hkdf(key: &[u8], input: &[u8]) -> [[u8; L]; 2] {
    let tmp = hmac_sha256(&input, &key);
    let output_1 = hmac_sha256(&[0x01], &tmp);

    let mut output_one_plus_two: [u8; 33] = [0; 33];
    output_one_plus_two[..32].copy_from_slice(&output_1);
    output_one_plus_two[32] = 0x02;

    let output_2 = hmac_sha256(&output_one_plus_two, &tmp);

    [output_1, output_2]
}
