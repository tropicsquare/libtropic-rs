#[cfg(test)]

mod unit {

    use sha2::{Digest, Sha256};
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::{
        aes_utils::init_aes256_gcm,
        frames::{
            Frame,
            handshake_req::{self, *},
        },
        hkdf::hkdf,
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
        let hkdf_output_1_part_1 = ascii_byte_string_to_bytes(
            "33F7C69BD317AF95C81CC9A936C154A3AA78FA5E6F8E21FA64C00A03689F6136",
        )
        .unwrap();
        let hkdf_output_1_part_2 = ascii_byte_string_to_bytes(
            "624EA2ED51C2162078A843E1E4352CCD192E1115DA8020438C43B7C3EA773E7F",
        )
        .unwrap();
        let shared_secret_2 = ascii_byte_string_to_bytes(
            "52E5C6165C29D0B2DDAA3D0233D08BA131FCD62DAA158D3FFA1922D8CE7B9A72",
        )
        .unwrap();
        let hkdf_output_2_part_1 = ascii_byte_string_to_bytes(
            "72AD33984797ECCBF53217631B7C959E02178A502A245FDD887A4CCCA8C9611F",
        )
        .unwrap();
        let hkdf_output_2_part_2 = ascii_byte_string_to_bytes(
            "3E26C7FCCD9126DB3A83BE8CDCBDC63693454C28BC2A487FDC37E750771F2E7F",
        )
        .unwrap();
        let shared_secret_3 = ascii_byte_string_to_bytes(
            "5D92D3E647EE6FA54FF9FD8B05871FD9D53CA54C0DF229A1F06B18B196577F74",
        )
        .unwrap();
        let hkdf_output_3_part_1 = ascii_byte_string_to_bytes(
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
        let mut hkdf_out_2: [u8; 32];

        // ck = hkdf_one_out(&ck, shared_secret.as_bytes());
        // assert_eq!(hkdf_output_1, ck);

        // println!("Protocol name: {:?}", bytes_to_hex_string(&protocol_name));
        // println!(
        //     "Shared secret: {:?}",
        //     bytes_to_hex_string(shared_secret.as_bytes())
        // );

        // ck = HKDF (ck, X25519(EHPRIV, ETPUB), 1)

        [ck, hkdf_out_2] = hkdf(&ck, &shared_secret_1.clone());

        // println!("{:#?}", bytes_to_hex_string(&output_1));
        assert_eq!(hkdf_output_1_part_1, ck);
        assert_eq!(hkdf_output_1_part_2, hkdf_out_2);

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
        // let tmp = hmac_sha256(&vec_to_array_32(shared_secret_2.clone()), &ck);
        // let output_1 = hmac_sha256(&[0x01], &tmp);
        // ck = output_1;
        // // println!("{:#?}", bytes_to_hex_string(&output_1));
        // assert_eq!(hkdf_output_3, ck);

        [ck, hkdf_out_2] = hkdf(&ck, &shared_secret_2.clone());

        assert_eq!(hkdf_output_2_part_1, ck);
        assert_eq!(hkdf_output_2_part_2, hkdf_out_2);

        let imported_secret = StaticSecret::from(vec_to_array_32(ehpriv));
        let imported_pub = PublicKey::from(vec_to_array_32(stpub));
        let shared_secret = imported_secret.diffie_hellman(&imported_pub);
        assert_eq!(shared_secret.as_bytes().to_vec(), shared_secret_3.to_vec());

        // ck , k AUTH = HKDF (ck, X25519(EHPRIV, STPUB), 2)

        [ck, hkdf_out_2] = hkdf(&ck, &shared_secret_3.clone());

        assert_eq!(hkdf_output_3_part_1, ck);
        assert_eq!(hkdf_kauth, hkdf_out_2);

        // k CMD , k RES = HKDF (ck, empty string , 2)
        [ck, hkdf_out_2] = hkdf(&ck, b"");

        assert_eq!(hkdf_kcmd, ck);
        assert_eq!(hkdf_kres, hkdf_out_2);

        let auth_tag = init_aes256_gcm(
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &vec_to_array_32(hkdf_kauth),
            &h,
        );

        assert_eq!(auth_tag, vec_to_array_16(t_tauth));
    }

    #[test]
    fn test_vectors_from_my_chip() {
        fn vec_to_array_32(vec: Vec<u8>) -> [u8; 32] {
            vec.try_into().expect("Vec must have length 32")
        }

        fn vec_to_array_16(vec: Vec<u8>) -> [u8; 16] {
            vec.try_into().expect("Vec must have length 16")
        }

        let protocol_name: [u8; 32] = *b"Noise_KK1_25519_AESGCM_SHA256\0\0\0";

        let stpub = ascii_byte_string_to_bytes(
            "e44436c00c62ff2678f20a7e99c2886e9af58188a3e2f364f4c21834a91a047f",
        )
        .unwrap();
        let shipriv = ascii_byte_string_to_bytes(
            "d09992b1f17abc4db9371768a27da05b18fab85613a7842ca64c7910f22e716b",
        )
        .unwrap();
        let shipub = ascii_byte_string_to_bytes(
            "e7f735ba19a33fd67323ab37262de53608ca578576534352e18f64e613d38d54",
        )
        .unwrap();
        let ehpriv = ascii_byte_string_to_bytes(
            "a7410000f13ad610d9acb7602a0cb53a82b73144c8da061cd88e0506fe09e556",
        )
        .unwrap();
        let ehpub = ascii_byte_string_to_bytes(
            "cf075a98910bd86aceeb6a5c979765243d73e7ed6bb3c115a6bee5dd555c222f",
        )
        .unwrap();
        let etpub = ascii_byte_string_to_bytes(
            "c792a398e06141ff0fff26ca41559aca396117ca36d15360e0936d56cac6785b",
        )
        .unwrap();
        let t_tauth = ascii_byte_string_to_bytes("a8c88653ae28724669855dc012e019ec").unwrap();
        let hash1 = ascii_byte_string_to_bytes(
            "dc3cec095541d8083c2d1af6b2f4030fa3d63e4d7870d6766c806060105ae8dc",
        )
        .unwrap();
        let hash2 = ascii_byte_string_to_bytes(
            "c87f956a4943b65f89786f6440f22cffbd3ac44b5dfa8ecfb5a8f3030efed678",
        )
        .unwrap();
        let hash3 = ascii_byte_string_to_bytes(
            "aa13b0796f92911ccdb3d77b447eb77954ec60c5bd29909164320f5b092173f8",
        )
        .unwrap();
        let hash4 = ascii_byte_string_to_bytes(
            "8c5cfc2809fa9cb595e587be7380296ee37619beeb965c8197e6d5fea5606b22",
        )
        .unwrap();
        let hash5 = ascii_byte_string_to_bytes(
            "0c629e54eadb1f7d5b005b880881bd9dec692371e28e908d728185b0e954d8b4",
        )
        .unwrap();
        let hash6 = ascii_byte_string_to_bytes(
            "d6190c5b80f3fc84a461207d019914e697a2065ec8cdb41765107ddf6b44749b",
        )
        .unwrap();
        let shared_secret_1 = ascii_byte_string_to_bytes(
            "457295c7263eb2ae95c0201ed8fce1128e8b9c54bcfd902f3872ae19df4a3e53",
        )
        .unwrap();
        let hkdf_output_1_part_1 = ascii_byte_string_to_bytes(
            "a37a8a83759ccb2fe456354b4597c2354724ea341cacc5e2b86037af797a25ab",
        )
        .unwrap();
        let hkdf_output_1_part_2 = ascii_byte_string_to_bytes(
            "5eb42fc12ef7deaecfa5a6d715313b48b32f98db935ce4658c12eb05984575c4",
        )
        .unwrap();
        let shared_secret_2 = ascii_byte_string_to_bytes(
            "84487495b84417cd8f3adf3e0c02484c1d1e553513cf4b61b4adb6992cf34477",
        )
        .unwrap();
        let hkdf_output_2_part_1 = ascii_byte_string_to_bytes(
            "346ae6e10a786fd0d7a63004bdb46061d7367d0798990112ef5a34bfff0dbbc6",
        )
        .unwrap();
        let hkdf_output_2_part_2 = ascii_byte_string_to_bytes(
            "b920344d9d7423c36dbe81aeebb53ca459149a9319cdceb259029bb1f4d6e1cd",
        )
        .unwrap();
        let shared_secret_3 = ascii_byte_string_to_bytes(
            "2a362f8c666703923d2d52d4b38f04faa99e9e2d311721bcc899be5a48167775",
        )
        .unwrap();
        let hkdf_output_3_part_1 = ascii_byte_string_to_bytes(
            "72f0715e3b981b613f872ce9dd4e2adefd280da2b89402382e8493298b2c2ae0",
        )
        .unwrap();
        let hkdf_kauth = ascii_byte_string_to_bytes(
            "81f5fc3513cc60e97c202aa88b514474e97169460a2ba51f038c02f16e9414df",
        )
        .unwrap();
        let hkdf_kcmd = ascii_byte_string_to_bytes(
            "6057256b85446c3f744debb1c7a11bca1163e32a902b203f6a66da293a4bbb29",
        )
        .unwrap();
        let hkdf_kres = ascii_byte_string_to_bytes(
            "cb4aca1c6b15600105d797131db53d8234c977f173098b45ef33fe890b9177a3",
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
        let mut hkdf_out_2: [u8; 32];

        // ck = hkdf_one_out(&ck, shared_secret.as_bytes());
        // assert_eq!(hkdf_output_1, ck);

        // println!("Protocol name: {:?}", bytes_to_hex_string(&protocol_name));
        // println!(
        //     "Shared secret: {:?}",
        //     bytes_to_hex_string(shared_secret.as_bytes())
        // );

        // ck = HKDF (ck, X25519(EHPRIV, ETPUB), 1)

        [ck, hkdf_out_2] = hkdf(&ck, &shared_secret_1.clone());

        // println!("{:#?}", bytes_to_hex_string(&output_1));
        assert_eq!(hkdf_output_1_part_1, ck);
        assert_eq!(hkdf_output_1_part_2, hkdf_out_2);

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
        // let tmp = hmac_sha256(&vec_to_array_32(shared_secret_2.clone()), &ck);
        // let output_1 = hmac_sha256(&[0x01], &tmp);
        // ck = output_1;
        // // println!("{:#?}", bytes_to_hex_string(&output_1));
        // assert_eq!(hkdf_output_3, ck);

        [ck, hkdf_out_2] = hkdf(&ck, &shared_secret_2.clone());

        assert_eq!(hkdf_output_2_part_1, ck);
        assert_eq!(hkdf_output_2_part_2, hkdf_out_2);

        let imported_secret = StaticSecret::from(vec_to_array_32(ehpriv));
        let imported_pub = PublicKey::from(vec_to_array_32(stpub));
        let shared_secret = imported_secret.diffie_hellman(&imported_pub);
        assert_eq!(shared_secret.as_bytes().to_vec(), shared_secret_3.to_vec());

        // ck , k AUTH = HKDF (ck, X25519(EHPRIV, STPUB), 2)

        [ck, hkdf_out_2] = hkdf(&ck, &shared_secret_3.clone());

        assert_eq!(hkdf_output_3_part_1, ck);
        assert_eq!(hkdf_kauth, hkdf_out_2);

        // k CMD , k RES = HKDF (ck, empty string , 2)
        [ck, hkdf_out_2] = hkdf(&ck, b"");

        assert_eq!(hkdf_kcmd, ck);
        assert_eq!(hkdf_kres, hkdf_out_2);

        let auth_tag = init_aes256_gcm(
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &vec_to_array_32(hkdf_kauth),
            &h,
        );

        assert_eq!(auth_tag, vec_to_array_16(t_tauth));
    }
}
