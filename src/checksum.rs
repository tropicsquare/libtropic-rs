pub fn crc16(data: &[u8]) -> [u8; 2] {
    let polynomial: u16 = 0x8005; // CRC-16 polynomial
    let mut crc: u16 = 0x0000; // Initialization vector

    for &byte in data {
        crc ^= (byte as u16) << 8; // XOR top byte with the current byte
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ polynomial;
            } else {
                crc <<= 1;
            }
        }
    }

    crc.to_le_bytes()
}

pub fn verify_checksum(frame: &Vec<u8>) -> bool {
    if frame.len() < 2 {
        return false; // Not enough data to contain a checksum
    }

    // Compute the checksum of the remaining frame
    let computed_checksum = crc16(&frame[0..&frame.len() - 2]);

    // Compare the computed checksum with the received checksum
    frame[&frame.len() - 2..frame.len()] == computed_checksum
}
