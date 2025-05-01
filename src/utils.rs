use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub fn hex_to_ascii(data: &[u8]) -> String {
    data.iter().map(|&byte| byte as char).collect()
}

pub fn strip_control_squences(input: &str) -> String {
    input
        .chars()
        .filter(|&c| !c.is_control()) // Filters out control characters like \r, \n, etc.
        .collect()
}

pub fn hex_str_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have an even number of characters".to_string());
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub fn ascii_bytes_to_dec(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0, |acc, &b| (acc << 8) | b as u32)
}

pub fn hex_str_to_dec(hex: &str) -> Result<usize, String> {
    usize::from_str_radix(hex, 16).map_err(|e| e.to_string())
}

pub fn bytes_to_ascii(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| byte as char).collect()
}

pub fn ascii_bytes_to_hex_to_ascii(bytes: Vec<u8>) -> String {
    bytes_to_ascii(&hex_str_to_bytes(&strip_control_squences(&hex_to_ascii(&bytes))).unwrap())
}

pub fn ascii_byte_string_to_bytes(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("Input string must have an even number of characters".to_string());
    }

    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub fn ascii_bytes_to_real_bytes(ascii: &[u8]) -> Result<Vec<u8>, String> {
    if ascii.len() % 2 != 0 {
        return Err("Input length must be even".into());
    }

    ascii
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).ok_or("Invalid hex digit")?;
            let lo = (pair[1] as char).to_digit(16).ok_or("Invalid hex digit")?;
            Ok((hi << 4 | lo) as u8)
        })
        .collect()
}

pub fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn extract_public_key_from_tropico_cert(cert: Vec<u8>) -> Result<[u8; 32], String> {
    let pattern = [0x65, 0x6e, 0x03, 0x21];
    if let Some(pos) = cert
        .windows(pattern.len())
        .position(|window| window == pattern)
    {
        let start = pos + pattern.len();
        if cert.len() >= start + 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&cert[start..start + 32]);
            Ok(key)
        } else {
            Err("The provided byte array is too short to contain a public key (minimum is 4 + 32 bytes)".to_string())
        }
    } else {
        Err("Pattern before key not found (0x65, 0x6e, 0x03, 0x21) not found".to_string())
    }
}

pub fn sha256(input: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    return result.to_vec();
}
