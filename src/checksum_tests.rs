#[cfg(test)]

mod unit {
    use crate::{checksum::verify_checksum, utils::hex_str_to_bytes};

    #[test]
    fn test_with_known_value() {
        let input = vec![0x01, 0x02, 0x01, 0x00];
        let expected_result = vec![0x2B, 0x92];
        assert_eq!(crate::checksum::crc16(&input).to_vec(), expected_result)
    }

    #[test]
    fn verification_works() {
        let input = vec![0x01, 0x02, 0x01, 0x00, 0x2B, 0x92];
        assert!(verify_checksum(&input));

        let input = vec![0x01, 0x02, 0x01, 0x00, 0x2B, 0x93];
        assert_eq!(verify_checksum(&input), false);
    }

    #[test]
    fn anything() {
        let frame = hex_str_to_bytes("041402004E928594F32C56AEB8A2EA9C30F2E471EA7C597B").unwrap();
        println!("{:#?}", verify_checksum(&frame));
    }
}
