#[cfg(test)]

mod unit {
    use crate::frames::{
        Frame,
        handshake_req::{self, *},
    };

    #[test]
    fn can_be_constructed() {
        let public_key: [u8; 32] = [
            0xCF, 0x07, 0x5A, 0x98, 0x91, 0x0B, 0xD8, 0x6A, 0xCE, 0xEB, 0x6A, 0x5C, 0x97, 0x97,
            0x65, 0x24, 0x3D, 0x73, 0xE7, 0xED, 0x6B, 0xB3, 0xC1, 0x15, 0xA6, 0xBE, 0xE5, 0xDD,
            0x55, 0x5C, 0x22, 0x2F,
        ];

        let req_data = ReqData {
            ephemeral_public_key: public_key,
            pairing_key_slot: pairing_key_slotIndex::Zero,
        };

        let handshake = HandshakeReqFrame { data: req_data };
        let bytes = handshake.as_bytes();

        let expected: Vec<u8> = vec![
            0x02, 0x21, 0xCF, 0x07, 0x5A, 0x98, 0x91, 0x0B, 0xD8, 0x6A, 0xCE, 0xEB, 0x6A, 0x5C,
            0x97, 0x97, 0x65, 0x24, 0x3D, 0x73, 0xE7, 0xED, 0x6B, 0xB3, 0xC1, 0x15, 0xA6, 0xBE,
            0xE5, 0xDD, 0x55, 0x5C, 0x22, 0x2F, 0x00, 0xA0, 0x47,
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn can_be_constructed_with_new_key() {
        use x25519_dalek::{EphemeralSecret, PublicKey};

        let host_secret = EphemeralSecret::random();
        let host_public = PublicKey::from(&host_secret);

        let handshake_req = HandshakeReqFrame {
            data: ReqData {
                ephemeral_public_key: *host_public.as_bytes(),
                pairing_key_slot: pairing_key_slotIndex::Zero,
            },
        };

        println!("{:#?}", handshake_req.as_bytes());
    }
}
