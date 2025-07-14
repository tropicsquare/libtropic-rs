use std::io::{self};
use std::{time::Duration, vec};

use frames::get_info_req::GetInfoReqFrame;
use frames::handshake_req::HandshakeReqFrame;

use libtropic_rs::*;

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::commands::get_random_bytes::GetRandomBytesCommand;
use crate::commands::ping::PingCommand;
use crate::frames::encrypted_cmd_req::EncryptedCmdReq;
use crate::hkdf::hkdf;

static sh0priv: [u8; 32] = [
    0xd0, 0x99, 0x92, 0xb1, 0xf1, 0x7a, 0xbc, 0x4d, 0xb9, 0x37, 0x17, 0x68, 0xa2, 0x7d, 0xa0, 0x5b,
    0x18, 0xfa, 0xb8, 0x56, 0x13, 0xa7, 0x84, 0x2c, 0xa6, 0x4c, 0x79, 0x10, 0xf2, 0x2e, 0x71, 0x6b,
];

static sh0pub: [u8; 32] = [
    0xe7, 0xf7, 0x35, 0xba, 0x19, 0xa3, 0x3f, 0xd6, 0x73, 0x23, 0xab, 0x37, 0x26, 0x2d, 0xe5, 0x36,
    0x08, 0xca, 0x57, 0x85, 0x76, 0x53, 0x43, 0x52, 0xe1, 0x8f, 0x64, 0xe6, 0x13, 0xd3, 0x8d, 0x54,
];

fn main() -> io::Result<()> {
    // let mut port = serialport::new("/dev/tty.usbmodem1b36003d37941", 115_200)
    let mut port = serialport::new("/dev/cu.usbmodem4982328A384B1", 115_200)
        .timeout(Duration::from_millis(10))
        .open()
        .expect("Failed to open port");

    let mut bytes: Vec<u8> = vec![];
    for cert_chunk in 0x00..=0x03 {
        let resp_obj_bytes = send_frame_and_get_response(
            &mut port,
            GetInfoReqFrame {
                data: get_info_req::ReqData::X509Certificate { chunk: cert_chunk },
            },
            Duration::from_millis(100),
        );

        // this response seems to come with a crc, so the last two bytes are cut
        println!(
            "appending bytes: {:#?}",
            bytes_to_hex_string(&resp_obj_bytes)
        );
        bytes.extend(resp_obj_bytes);

        println!("Got chunk: {:#?}", cert_chunk);
    }

    // println!(
    //     "X.509 Cert: {:#?}",
    //     strip_control_squences(&bytes_to_ascii(&bytes))
    // );

    // println!("X.509 (hex): {:#?}", bytes_to_hex_string(&bytes));

    let stpub = extract_public_key_from_tropico_cert(bytes)
        .unwrap_or_else(|_| panic!("Could not extract chip public key; line: {}", line!()));

    println!(
        "Chip public key from cert: {:#?}",
        bytes_to_hex_string(&stpub)
    );

    let resp_obj_bytes = send_frame_and_get_response(
        &mut port,
        GetInfoReqFrame {
            data: get_info_req::ReqData::ChipID,
        },
        Duration::from_millis(150),
    );

    let resp_ob = strip_control_squences(&bytes_to_ascii(&resp_obj_bytes.to_vec()));

    println!("Chip ID: {:#?}", resp_ob);

    let resp_obj_bytes = send_frame_and_get_response(
        &mut port,
        GetInfoReqFrame {
            data: get_info_req::ReqData::RiscvFwVersion,
        },
        Duration::from_millis(150),
    );

    let resp_ob = strip_control_squences(&bytes_to_ascii(&resp_obj_bytes));

    println!("Riscv Fw Version: {:#?}", resp_ob);

    let resp_obj_bytes = send_frame_and_get_response(
        &mut port,
        GetInfoReqFrame {
            data: get_info_req::ReqData::SpectFwVersion,
        },
        Duration::from_millis(0),
    );

    let resp_ob = strip_control_squences(&bytes_to_ascii(&resp_obj_bytes));

    println!("Spect Fw Version: {:#?}", resp_ob);

    // let ehpriv = ReusableSecret::random();
    let ehpriv = StaticSecret::random();
    let ehpub = PublicKey::from(&ehpriv);

    let resp_obj_bytes = send_frame_and_get_response(
        &mut port,
        HandshakeReqFrame {
            data: handshake_req::ReqData {
                ephemeral_public_key: *ehpub.as_bytes(),
                pairing_key_slot: handshake_req::pairing_key_slotIndex::Zero,
            },
        },
        Duration::from_millis(150),
    );

    println!("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++=");

    println!(
        "Chip auth package: {:#?}",
        bytes_to_hex_string(&resp_obj_bytes)
    );
    let chip_ephemeral_key_bytes = resp_obj_bytes[..32.min(resp_obj_bytes.len())].to_vec();
    let auth_tag_chip = resp_obj_bytes[32..48.min(resp_obj_bytes.len())].to_vec();

    println!(
        "Chip ephemeral key: {:#?}",
        bytes_to_hex_string(&chip_ephemeral_key_bytes)
    );

    println!("Auth tag: {:#?}", bytes_to_hex_string(&auth_tag_chip));

    let ephemeral_key_bytes_sized: [u8; 32] = chip_ephemeral_key_bytes
        .try_into()
        .unwrap_or_else(|_| panic!("Invalid length; line: {}", line!()));
    let chip_ephemeral_public_key = PublicKey::from(ephemeral_key_bytes_sized);
    let etpub = chip_ephemeral_public_key.as_bytes();
    assert_eq!(&ephemeral_key_bytes_sized, etpub);

    // let stpub = ascii_byte_string_to_bytes(
    //     "e44436c00c62ff2678f20a7e99c2886e9af58188a3e2f364f4c21834a91a047f",
    // )
    // .unwrap();
    // let shipriv = ascii_byte_string_to_bytes(
    //     "d09992b1f17abc4db9371768a27da05b18fab85613a7842ca64c7910f22e716b",
    // )
    // .unwrap();
    // let shipub = ascii_byte_string_to_bytes(
    //     "e7f735ba19a33fd67323ab37262de53608ca578576534352e18f64e613d38d54",
    // )
    // .unwrap();

    let protocol_name: [u8; 32] = *b"Noise_KK1_25519_AESGCM_SHA256\0\0\0";

    let mut hasher = Sha256::new();
    hasher.update(&protocol_name);
    let mut h = hasher.finalize_reset(); // hash: GenericArray<u8, U32>
    println!("{:#?}", bytes_to_hex_string(&h));

    // h = SHA256(h || shipub)
    hasher.update(&h);
    hasher.update(&sh0pub); // shipub must be [u8; 32]
    h = hasher.finalize_reset();
    println!("{:#?}", bytes_to_hex_string(&h));

    // h = SHA256(h||STPUB)
    hasher.update(&h);
    hasher.update(&stpub); // shipub must be [u8; 32]
    h = hasher.finalize_reset();
    println!("{:#?}", bytes_to_hex_string(&h));

    // h = SHA256(h||EHPUB)
    hasher.update(&h);
    hasher.update(&ehpub.as_bytes().to_vec()); // shipub must be [u8; 32]
    h = hasher.finalize_reset();
    println!("{:#?}", bytes_to_hex_string(&h));

    // h = SHA256(h||PKEY_INDEX)
    hasher.update(&h);
    hasher.update([0x00]); // shipub must be [u8; 32]
    h = hasher.finalize_reset();
    println!("{:#?}", bytes_to_hex_string(&h));

    hasher.update(&h);
    hasher.update(&etpub.to_vec());
    h = hasher.finalize_reset();
    println!("{:#?}", bytes_to_hex_string(&h));

    let imported_pub = PublicKey::from(*etpub);
    let shared_secret = ehpriv.diffie_hellman(&imported_pub);

    let mut ck = protocol_name.clone();

    [ck, _] = hkdf(&ck, shared_secret.as_bytes());

    let imported_secret = StaticSecret::from(sh0priv);
    let imported_pub = PublicKey::from(*etpub);
    let shared_secret = imported_secret.diffie_hellman(&imported_pub);

    [ck, _] = hkdf(&ck, shared_secret.as_bytes());

    let imported_pub = PublicKey::from(stpub);
    let shared_secret = ehpriv.diffie_hellman(&imported_pub);

    let mut k_auth: [u8; 32];
    [ck, k_auth] = hkdf(&ck, shared_secret.as_bytes());

    let mut kcmd: [u8; 32];
    let mut kres: [u8; 32];
    [kcmd, kres] = hkdf(&ck, b"");

    let (_, auth_tag) = aes256_gcm(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &k_auth, b"", &h);

    assert_eq!(auth_tag, auth_tag_chip[0..16]);

    println!("{:#?}", bytes_to_hex_string(&auth_tag));

    // let cmd = (PingCommand {
    //     data: vec![0xff, 0xdd],
    // })
    // .as_bytes();

    let cmd = (GetRandomBytesCommand { n_bytes: 0 }).as_bytes();

    let mut cmd_enc_and_tag =
        aes256_gcm_concat(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &kcmd, &cmd, b"");

    // the conversion takes the len and creates a two byte representation up to 4096, least significant byte first
    cmd_enc_and_tag.splice(0..0, (cmd.len() as u16).to_le_bytes()); // pretty sure this is len and chunk number

    println!(
        "cmd_enc_and_tag: {:#?}",
        bytes_to_hex_string(&cmd_enc_and_tag)
    );

    let resp_obj_bytes = send_frame_and_get_req_cont(
        &mut port,
        EncryptedCmdReq {
            data: encrypted_cmd_req::ReqData {
                encryped_command: cmd_enc_and_tag.clone(),
            },
        },
        Duration::from_millis(150),
    );

    println!("{:#?}", resp_obj_bytes);
    let resp_obj_bytes = get_next_response(&mut port, Duration::from_millis(150));
    // println!("{:#?}", resp_obj_bytes);

    let dec = aes256_gcm_decrypt(
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &kres,
        &resp_obj_bytes[2..],
        b"",
    );

    if dec[0] == 0xc3 {
        println!("Command sucessfully executed (c3)");
    }

    println!(
        "Command returned: {:#?} (mind the padding)",
        bytes_to_hex_string(&dec)
    );

    Ok(())
}
