#[cfg(test)]

mod unit {

    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::{
        aes_utils::init_aes256_gcm,
        frames::{
            Frame,
            handshake_req::{self, *},
        },
        utils::{ascii_byte_string_to_bytes, bytes_to_ascii, bytes_to_hex_string, hkdf_one_out},
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

    #[test]
    fn test_vectors() {
        use hmac::{Hmac, Mac};
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

        fn vec_to_array_32(vec: Vec<u8>) -> [u8; 32] {
            vec.try_into().expect("Vec must have length 32")
        }

        fn vec_to_array_16(vec: Vec<u8>) -> [u8; 16] {
            vec.try_into().expect("Vec must have length 16")
        }

        let protocol_name: [u8; 32] = *b"Noise_KK1_25519_AESGCM_SHA256\0\0\0";

        let stpub = ascii_byte_string_to_bytes(
            "31E90AF1504510EE4EFD79133341481589A2895CC5FBB13ED5711C1E9B819872",
        )
        .unwrap();
        let shipriv = ascii_byte_string_to_bytes(
            "F0C4AA048F0013A09684DF05E8A22EF7213898282BA94312F313DF2DCE8D4164",
        )
        .unwrap();
        let shipub = ascii_byte_string_to_bytes(
            "842FE321A82474083737FF2B9B88A2AF42442DB0D8AACC6DC69E99533344B246",
        )
        .unwrap();
        let ehpriv = ascii_byte_string_to_bytes(
            "CDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDAB",
        )
        .unwrap();
        let ehpub = ascii_byte_string_to_bytes(
            "2E55B205DD31B397E6BCEF3C028135ED58365A0F763CFB799E8A01AC2372271F",
        )
        .unwrap();
        let etpub = ascii_byte_string_to_bytes(
            "053432FDF0EABD2444AE0151FAB1EA44C0BF1D6788EC572EC2ED56D6020A8945",
        )
        .unwrap();
        let t_tauth = ascii_byte_string_to_bytes("78AADC7E4415FD0FA76CBB806EE380F1").unwrap();
        let hash1 = ascii_byte_string_to_bytes(
            "DC3CEC095541D8083C2D1AF6B2F4030FA3D63E4D7870D6766C806060105AE8DC",
        )
        .unwrap();
        let hash2 = ascii_byte_string_to_bytes(
            "EBF14B10E71AEEA09A0B3486A691C821329E1D81E661AFE701CC98AD0D3779FE",
        )
        .unwrap();
        let hash3 = ascii_byte_string_to_bytes(
            "3345F22186F96227AAD059F50B225D6846AD15144491F861A38F88E6EF1D8868",
        )
        .unwrap();
        let hash4 = ascii_byte_string_to_bytes(
            "42165BBF07B850D614D49B316BF5398DAE13CEEECE66F320303A9A557EA56432",
        )
        .unwrap();
        let hash5 = ascii_byte_string_to_bytes(
            "5F76F6B977CEE2179F3DC21F08648B79ECD52615A68CB30FEDFB460F75EFFA7E",
        )
        .unwrap();
        let hash6 = ascii_byte_string_to_bytes(
            "0C28DD2D8BD74D2E82265AC646E1893915B58A7671E5D46CD3CE6EC4D4F07D82",
        )
        .unwrap();
        let shared_secret_1 = ascii_byte_string_to_bytes(
            "8E3F0E9AB5CDC649207A30ED62F576569FE225B20E165AF7B330C4926C97047F",
        )
        .unwrap();
        let hkdf_output_1 = ascii_byte_string_to_bytes(
            "33F7C69BD317AF95C81CC9A936C154A3AA78FA5E6F8E21FA64C00A03689F6136",
        )
        .unwrap();
        let _hkdf_output_2_unused = ascii_byte_string_to_bytes(
            "624EA2ED51C2162078A843E1E4352CCD192E1115DA8020438C43B7C3EA773E7F",
        )
        .unwrap();
        let shared_secret_2 = ascii_byte_string_to_bytes(
            "52E5C6165C29D0B2DDAA3D0233D08BA131FCD62DAA158D3FFA1922D8CE7B9A72",
        )
        .unwrap();
        let hkdf_output_3 = ascii_byte_string_to_bytes(
            "72AD33984797ECCBF53217631B7C959E02178A502A245FDD887A4CCCA8C9611F",
        )
        .unwrap();
        let _hkdf_output_2_unused = ascii_byte_string_to_bytes(
            "3E26C7FCCD9126DB3A83BE8CDCBDC63693454C28BC2A487FDC37E750771F2E7F",
        )
        .unwrap();
        let shared_secret_3 = ascii_byte_string_to_bytes(
            "5D92D3E647EE6FA54FF9FD8B05871FD9D53CA54C0DF229A1F06B18B196577F74",
        )
        .unwrap();
        let hkdf_output_4 = ascii_byte_string_to_bytes(
            "7075FA2907DBA32633E6FD83CF1B5E5A059F572B1D8669751D082028AE081CBB",
        )
        .unwrap();
        let hkdf_kauth = ascii_byte_string_to_bytes(
            "9F9A0288E1811AD52237FCAE845EECD69A7A1471ABDB85E6BD7769610D02F026",
        )
        .unwrap();
        let hkdf_kcmd = ascii_byte_string_to_bytes(
            "DE295C92AA61F49186D8623C5B4F3308B426D6B70A908F230032523AA126EE57",
        )
        .unwrap();
        let hkdf_kres = ascii_byte_string_to_bytes(
            "CC3FCEE961C3B851B0178880344B91E7520B427F55AE7CA0270504EA6E58F109",
        )
        .unwrap();
        // let iv = ascii_byte_string_to_bytes("000000000000000000000000");

        let mut hasher = Sha256::new();
        hasher.update(&protocol_name);
        let mut h = hasher.finalize_reset(); // hash: GenericArray<u8, U32>

        assert_eq!(h.to_vec(), hash1);

        // h = SHA256(h || shipub)
        hasher.update(&h);
        hasher.update(&shipub); // shipub must be [u8; 32]
        h = hasher.finalize_reset();

        assert_eq!(h.to_vec(), hash2);

        // h = SHA256(h||STPUB)
        hasher.update(&h);
        hasher.update(&stpub); // shipub must be [u8; 32]
        h = hasher.finalize_reset();

        assert_eq!(h.to_vec(), hash3);

        // h = SHA256(h||EHPUB)
        hasher.update(&h);
        hasher.update(&ehpub); // shipub must be [u8; 32]
        h = hasher.finalize_reset();

        assert_eq!(h.to_vec(), hash4);

        // h = SHA256(h||PKEY_INDEX)
        hasher.update(&h);
        hasher.update([0x00]); // shipub must be [u8; 32]
        h = hasher.finalize_reset();

        assert_eq!(h.to_vec(), hash5);

        hasher.update(&h);
        hasher.update(&etpub);
        h = hasher.finalize_reset();
        assert_eq!(h.to_vec(), hash6);

        let imported_secret = StaticSecret::from(vec_to_array_32(ehpriv.clone()));
        let imported_pub = PublicKey::from(vec_to_array_32(etpub.clone()));
        let shared_secret = imported_secret.diffie_hellman(&imported_pub);
        assert_eq!(shared_secret.as_bytes().to_vec(), shared_secret_1.to_vec());

        let mut ck = protocol_name.clone();

        // ck = hkdf_one_out(&ck, shared_secret.as_bytes());
        // assert_eq!(hkdf_output_1, ck);

        // println!("Protocol name: {:?}", bytes_to_hex_string(&protocol_name));
        // println!(
        //     "Shared secret: {:?}",
        //     bytes_to_hex_string(shared_secret.as_bytes())
        // );

        // ck = HKDF (ck, X25519(EHPRIV, ETPUB), 1)
        ck = protocol_name.clone();
        let tmp = hmac_sha256(&vec_to_array_32(shared_secret_1.clone()), &ck);
        let output_1 = hmac_sha256(&[0x01], &tmp);
        ck = output_1;

        // println!("{:#?}", bytes_to_hex_string(&output_1));
        assert_eq!(hkdf_output_1, ck);

        // ck = protocol_name.clone();

        // type HmacSha256 = Hmac<Sha256>;
        // let mut hmac = HmacSha256::new_from_slice(&ck).unwrap();
        // hmac.update(&vec_to_array_32(shared_secret_1));
        // let tmp = hmac.finalize().into_bytes();

        // let mut hmac1 = HmacSha256::new_from_slice(&tmp).unwrap();
        // hmac1.update(&[0x01]);
        // let output_1 = hmac1.finalize().into_bytes();

        // println!("{:?}", bytes_to_hex_string(&output_1));

        let imported_secret = StaticSecret::from(vec_to_array_32(shipriv));
        let imported_pub = PublicKey::from(vec_to_array_32(etpub));
        let shared_secret = imported_secret.diffie_hellman(&imported_pub);
        assert_eq!(shared_secret.as_bytes().to_vec(), shared_secret_2.to_vec());

        // ck = HKDF (ck, X25519(SHiPRIV, ETPUB), 1)
        let tmp = hmac_sha256(&vec_to_array_32(shared_secret_2.clone()), &ck);
        let output_1 = hmac_sha256(&[0x01], &tmp);
        ck = output_1;
        // println!("{:#?}", bytes_to_hex_string(&output_1));
        assert_eq!(hkdf_output_3, ck);

        let imported_secret = StaticSecret::from(vec_to_array_32(ehpriv));
        let imported_pub = PublicKey::from(vec_to_array_32(stpub));
        let shared_secret = imported_secret.diffie_hellman(&imported_pub);
        assert_eq!(shared_secret.as_bytes().to_vec(), shared_secret_3.to_vec());

        // ck , k AUTH = HKDF (ck, X25519(EHPRIV, STPUB), 2)

        let tmp = hmac_sha256(&vec_to_array_32(shared_secret_3.clone()), &ck);
        let output_1 = hmac_sha256(&[0x01], &tmp);
        ck = output_1.clone();

        assert_eq!(hkdf_output_4, ck);

        let mut output_one_plus_two: [u8; 33] = [0; 33];
        output_one_plus_two[..32].copy_from_slice(&output_1);
        output_one_plus_two[32] = 0x02;

        let output_2 = hmac_sha256(&output_one_plus_two, &tmp);

        assert_eq!(hkdf_kauth, output_2);

        // k CMD , k RES = HKDF (ck, empty string , 2)
        let tmp = hmac_sha256(b"", &ck);
        let output_1 = hmac_sha256(&[0x01], &tmp);

        let mut output_one_plus_two: [u8; 33] = [0; 33];
        output_one_plus_two[..32].copy_from_slice(&output_1);
        output_one_plus_two[32] = 0x02;

        let output_2 = hmac_sha256(&output_one_plus_two, &tmp);

        assert_eq!(hkdf_kcmd, output_1);
        assert_eq!(hkdf_kres, output_2);

        let auth_tag = init_aes256_gcm(
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &vec_to_array_32(hkdf_kauth),
            &h,
        );

        // println!("{:#?}", bytes_to_hex_string(&auth_tag));
        assert_eq!(auth_tag, vec_to_array_16(t_tauth));
    }
}
