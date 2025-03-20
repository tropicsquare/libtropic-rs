#[cfg(test)]

mod unit {

    #[test]
    fn test_with_known_value() {
        let input = vec![0x01, 0x02, 0x01, 0x00];
        let expected_result = vec![0x2B, 0x92];
        assert_eq!(crate::checksum::crc16(&input).to_vec(), expected_result)
    }
}
