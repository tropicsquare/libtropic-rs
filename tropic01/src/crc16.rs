// The final XOR value is xored to the final CRC value before being returned.
// This is done after the 'Result reflected' step.
const CRC16_FINAL_XOR_VALUE: u16 = 0x0000;
// Used to initialize the crc value
const CRC16_INITIAL_VAL: u16 = 0x0000;
// Generator polynomial value used
const CRC16_POLYNOMIAL: u16 = 0x8005;

#[derive(Debug)]
#[repr(C)]
pub(super) struct Crc16(u16);

impl Crc16 {
    pub const fn new() -> Self {
        Crc16(CRC16_INITIAL_VAL)
    }

    pub fn update(&mut self, msg: &[u8]) {
        for current_byte in msg {
            crc_byte(&mut self.0, *current_byte);
        }
    }

    pub const fn get(mut self) -> u16 {
        self.0 ^= CRC16_FINAL_XOR_VALUE;
        self.0.rotate_right(8)
    }
}

fn crc_byte(crc: &mut u16, current_byte: u8) {
    let current_byte = current_byte as u16;
    *crc ^= current_byte << 8;
    for _ in 0..8 {
        if *crc & 0x8000 != 0 {
            *crc <<= 1;
            *crc ^= CRC16_POLYNOMIAL;
        } else {
            *crc <<= 1;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::crc16::Crc16;

    #[test]
    fn minimal_crc16_works() {
        let data = [0x0];
        let mut crc = Crc16::new();
        crc.update(&data);
        assert_eq!(0x0, crc.get());
    }

    #[test]
    fn short_body_crc16_works() {
        let data = [0x01, 0x02, 0x01, 0x01];
        let mut crc = Crc16::new();
        crc.update(&data);
        assert_eq!(0x2e12, crc.get());
    }

    #[test]
    fn long_body_crc16_works() {
        let data = [
            1, 1, 128, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 5, 68, 0, 0, 0, 0, 255, 255, 255, 255,
            255, 255, 1, 240, 15, 0, 5, 68, 84, 83, 84, 48, 49, 3, 0, 44, 0, 23, 11, 84, 82, 79,
            80, 73, 67, 48, 49, 45, 69, 83, 255, 255, 255, 255, 0, 1, 0, 0, 0, 0, 255, 255, 0, 1,
            0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0,
        ];
        let mut crc = Crc16::new();
        crc.update(&data);
        assert_eq!(0x8331, crc.get());
    }
}
