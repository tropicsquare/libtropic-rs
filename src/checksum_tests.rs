#[cfg(test)]

mod unit {
    use crate::checksum::verify_checksum;

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
        use x25519_dalek::{EphemeralSecret, PublicKey};
        let alice_secret = EphemeralSecret::random();
        let alice_public = PublicKey::from(&alice_secret);
        let bob_secret = EphemeralSecret::random();
        let bob_public = PublicKey::from(&bob_secret);
        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
        let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);
        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
    }
}
