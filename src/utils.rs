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

pub fn ascii_bytes_to_bytes(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("Input string must have an even number of characters".to_string());
    }

    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
