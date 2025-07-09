use std::io::{self, Read, Write};
use std::thread;
use std::{time::Duration, vec};

use frames::get_info_req::GetInfoReqFrame;
use frames::handshake_req::HandshakeReqFrame;
use serialport::SerialPort;

mod utils;
use utils::*;

mod frames;
use frames::*;

mod checksum;
mod checksum_tests;
use checksum::*;

mod aes_utils;
use aes_utils::*;

mod hkdf;
mod hkdf_tests;

mod commands;
use commands::*;

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};

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

    // let auth_tag = init_aes256_gcm(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &k_auth, &h);
    let (_, auth_tag) = aes256_gcm(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &k_auth, b"", &h);

    assert_eq!(auth_tag, auth_tag_chip[0..16]);

    println!("{:#?}", bytes_to_hex_string(&auth_tag));

    // let cmd = [0x50, 0x20]; // get a 32 byte random number

    let mut ping_cmd_data_too_large = Vec::with_capacity(600);
    for n in 0u8..=119 {
        ping_cmd_data_too_large.extend(std::iter::repeat(n).take(5));
    }

    println!("{:#?}", ping_cmd_data_too_large);

    // let cmd = (PingCommand {
    //     data: vec![0xff, 0xdd],
    // })
    // .as_bytes();

    let cmd = (PingCommand {
        data: ping_cmd_data_too_large,
    })
    .as_bytes();

    let mut cmd_enc_and_tag =
        aes256_gcm_concat(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &kcmd, &cmd, b"");

    let split_cmd_chunks: Vec<Vec<u8>> = cmd_enc_and_tag
        .chunks(252)
        .map(|chunk| chunk.to_vec())
        .collect();

    // the conversion takes the len and creates a two byte representation up to 4096, least significant byte first
    cmd_enc_and_tag.splice(0..0, (cmd_enc_and_tag.len() as u16).to_le_bytes()); // pretty sure this is len and chunk number

    println!(
        "cmd_enc_and_tag: {:#?}",
        bytes_to_hex_string(&cmd_enc_and_tag)
    );

    let resp_obj_bytes = send_frame_and_get_req_cont(
        &mut port,
        EncryptedCmdReq {
            data: encrypted_cmd_req::ReqData {
                encryped_command: split_cmd_chunks[0].clone(),
            },
        },
        Duration::from_millis(150),
    );

    // println!("{:#?}", resp_obj_bytes);
    // let resp_obj_bytes = get_next_response(&mut port, Duration::from_millis(150));
    // // println!("{:#?}", resp_obj_bytes);

    // let dec = aes256_gcm_decrypt(
    //     &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    //     &kres,
    //     &resp_obj_bytes[2..],
    //     b"",
    // );

    // if dec[0] == 0xc3 {
    //     println!("Command sucessfully executed (c3)");
    // }

    // println!(
    //     "Command returned: {:#?} (mind the padding)",
    //     bytes_to_hex_string(&dec)
    // );

    Ok(())
}

fn send_frame_and_get_response<T: Frame>(
    port: &mut Box<dyn SerialPort>,
    frame: T,
    sleep_duration_to_read_result: Duration,
) -> Vec<u8> {
    // CS =0
    set_cs_high(port).unwrap_or_else(|_| panic!("Could not set CS; line: {}", line!()));

    // Should respond OK\n (3 bytes)
    read_from_port(port, 3).unwrap_or_else(|_| panic!("Could not read; line: {}", line!()));

    let wrote_bytes = send_l2_frame(frame.as_bytes(), port)
        .unwrap_or_else(|_| panic!("Could not write; line: {}", line!()));

    read_from_port(port, wrote_bytes)
        .unwrap_or_else(|_| panic!("Could not read; line: {}", line!()));

    set_cs_high(port).unwrap_or_else(|_| panic!("Could not set CS; line: {}", line!()));

    read_from_port(port, 3).unwrap_or_else(|_| panic!("Could not read; line: {}", line!()));

    let mut resp = vec![0, 0, 0, 0];
    let ok_resp = vec![48, 49, 13, 10]; // "01" in ascii

    while resp != ok_resp {
        thread::sleep(sleep_duration_to_read_result);

        set_cs_high(port).unwrap_or_else(|_| panic!("Could not set CS; line: {}", line!()));
        read_from_port(port, 3).unwrap_or_else(|_| panic!("Could not read; line: {}", line!()));

        send_response_request(port)
            .unwrap_or_else(|_| panic!("Could not send response request; line: {}", line!()));

        resp = read_from_port(port, 4)
            .unwrap_or_else(|_| panic!("Could not read response size; line: {}", line!()));
    }

    send_response_size_request(port)
        .unwrap_or_else(|_| panic!("Could not send response size request; line: {}", line!()));

    let resp = read_from_port(port, 8)
        .unwrap_or_else(|_| panic!("Could not read response size; line: {}", line!()));
    let resp_str = strip_control_squences(&hex_to_ascii(&resp));

    // for some reason, there is an extraneous 01 (ok) before the response len
    let resp_len = hex_str_to_dec(&resp_str[2..])
        .unwrap_or_else(|_| panic!("Could not convert from hex str to dec; line: {}", line!()));
    let _ = write_n_junk_bytes(port, resp_len + 2)
        .unwrap_or_else(|_| panic!("Could not write junk; line: {}", line!()));

    #[cfg(debug_assertions)]
    println!("Response len: {:#?}", resp_len);

    // add 2 bytes for crc
    let resp_obj_ascii_bytes = read_from_port(port, resp_len + 2)
        .unwrap_or_else(|_| panic!("Could not read chip ID; line: {}", line!()));

    let mut resp_bytes = ascii_bytes_to_real_bytes(&resp_obj_ascii_bytes)
        .unwrap_or_else(|_| panic!("Could not convert ascii bytes to bytes; line: {}", line!()));

    // TODO: find out why this doesn't work and make it work
    // if !verify_checksum(&resp_bytes) {
    //     panic!();
    // }

    // return without crc
    resp_bytes.truncate(resp_bytes.len() - 2);
    return resp_bytes;
}

fn send_frame_and_get_req_cont<T: Frame>(
    port: &mut Box<dyn SerialPort>,
    frame: T,
    sleep_duration_to_read_result: Duration,
) -> Vec<u8> {
    // CS =0
    set_cs_high(port).unwrap_or_else(|_| panic!("Could not set CS; line: {}", line!()));

    // Should respond OK\n (3 bytes)
    read_from_port(port, 3).unwrap_or_else(|_| panic!("Could not read; line: {}", line!()));

    let wrote_bytes = send_l2_frame(frame.as_bytes(), port)
        .unwrap_or_else(|_| panic!("Could not write; line: {}", line!()));

    read_from_port(port, wrote_bytes)
        .unwrap_or_else(|_| panic!("Could not read; line: {}", line!()));

    set_cs_high(port).unwrap_or_else(|_| panic!("Could not set CS; line: {}", line!()));

    read_from_port(port, 3).unwrap_or_else(|_| panic!("Could not read; line: {}", line!()));

    let mut resp = vec![0, 0, 0, 0];
    let req_cont = vec![48, 49, 13, 10]; // "01" in ascii

    while resp != req_cont {
        thread::sleep(sleep_duration_to_read_result);

        set_cs_high(port).unwrap_or_else(|_| panic!("Could not set CS; line: {}", line!()));
        read_from_port(port, 3).unwrap_or_else(|_| panic!("Could not read; line: {}", line!()));

        send_response_request(port)
            .unwrap_or_else(|_| panic!("Could not send response request; line: {}", line!()));

        resp = read_from_port(port, 4)
            .unwrap_or_else(|_| panic!("Could not read response size; line: {}", line!()));
    }

    send_response_size_request(port)
        .unwrap_or_else(|_| panic!("Could not send response size request; line: {}", line!()));

    let resp = read_from_port(port, 8)
        .unwrap_or_else(|_| panic!("Could not read response size; line: {}", line!()));
    let resp_str = strip_control_squences(&hex_to_ascii(&resp));

    // for some reason, there is an extraneous 01 (ok) before the response len
    let resp_len = hex_str_to_dec(&resp_str[2..])
        .unwrap_or_else(|_| panic!("Could not convert from hex str to dec; line: {}", line!()));
    let _ = write_n_junk_bytes(port, resp_len + 2)
        .unwrap_or_else(|_| panic!("Could not write junk; line: {}", line!()));

    #[cfg(debug_assertions)]
    println!("Response len: {:#?}", resp_len);

    // add 2 bytes for crc
    let resp_obj_ascii_bytes = read_from_port(port, resp_len + 2)
        .unwrap_or_else(|_| panic!("Could not read chip ID; line: {}", line!()));

    let mut resp_bytes = ascii_bytes_to_real_bytes(&resp_obj_ascii_bytes)
        .unwrap_or_else(|_| panic!("Could not convert ascii bytes to bytes; line: {}", line!()));

    // TODO: find out why this doesn't work and make it work
    // if !verify_checksum(&resp_bytes) {
    //     panic!();
    // }

    // return without crc
    resp_bytes.truncate(resp_bytes.len() - 2);
    return resp_bytes;
}

fn get_next_response(
    port: &mut Box<dyn SerialPort>,
    sleep_duration_to_read_result: Duration,
) -> Vec<u8> {
    let mut resp = vec![0, 0, 0, 0];
    let ok_resp = vec![48, 49, 13, 10]; // "01" in ascii

    while resp != ok_resp {
        thread::sleep(sleep_duration_to_read_result);

        set_cs_high(port).unwrap_or_else(|_| panic!("Could not set CS; line: {}", line!()));
        read_from_port(port, 3).unwrap_or_else(|_| panic!("Could not read; line: {}", line!()));

        send_response_request(port)
            .unwrap_or_else(|_| panic!("Could not send response request; line: {}", line!()));

        resp = read_from_port(port, 4)
            .unwrap_or_else(|_| panic!("Could not read response size; line: {}", line!()));
    }

    send_response_size_request(port)
        .unwrap_or_else(|_| panic!("Could not send response size request; line: {}", line!()));

    let resp = read_from_port(port, 8)
        .unwrap_or_else(|_| panic!("Could not read response size; line: {}", line!()));
    let resp_str = strip_control_squences(&hex_to_ascii(&resp));

    // for some reason, there is an extraneous 01 (ok) before the response len
    let resp_len = hex_str_to_dec(&resp_str[2..])
        .unwrap_or_else(|_| panic!("Could not convert from hex str to dec; line: {}", line!()));
    let _ = write_n_junk_bytes(port, resp_len + 2)
        .unwrap_or_else(|_| panic!("Could not write junk; line: {}", line!()));

    #[cfg(debug_assertions)]
    println!("Response len: {:#?}", resp_len);

    // add 2 bytes for crc
    let resp_obj_ascii_bytes = read_from_port(port, resp_len + 2)
        .unwrap_or_else(|_| panic!("Could not read chip ID; line: {}", line!()));

    let mut resp_bytes = ascii_bytes_to_real_bytes(&resp_obj_ascii_bytes)
        .unwrap_or_else(|_| panic!("Could not convert ascii bytes to bytes; line: {}", line!()));

    // TODO: find out why this doesn't work and make it work
    // if !verify_checksum(&resp_bytes) {
    //     panic!();
    // }

    // return without crc
    resp_bytes.truncate(resp_bytes.len() - 2);
    return resp_bytes;
}

fn send_l2_frame(frame: Vec<u8>, port: &mut Box<dyn SerialPort>) -> io::Result<usize> {
    let frame = frame.clone();

    if !verify_checksum(&frame) {
        panic!("Frame crc invalid!")
    }

    let mut frame_hex: String = frame.iter().map(|b| format!("{:02X}", b)).collect();
    frame_hex.push_str("x\n");

    #[cfg(debug_assertions)]
    println!("Writing: {:#?}", frame_hex);

    port.write(frame_hex.as_bytes())
}

fn write_n_junk_bytes(port: &mut Box<dyn SerialPort>, n: usize) -> io::Result<usize> {
    let mut f_string = "FF".repeat(n);
    f_string.push_str("x\n");

    #[cfg(debug_assertions)]
    println!("Writing {} junk bytes: {:#?}", n, f_string);
    port.write(f_string.as_bytes())
}

fn set_cs_high(port: &mut Box<dyn SerialPort>) -> io::Result<usize> {
    #[cfg(debug_assertions)]
    println!("Writing: CS=0\\n");
    port.write(b"CS=0\n")
}

fn send_response_request(port: &mut Box<dyn SerialPort>) -> io::Result<usize> {
    #[cfg(debug_assertions)]
    println!("Writing: AAx\\n");
    port.write(b"AAx\n")
}

fn send_response_size_request(port: &mut Box<dyn SerialPort>) -> io::Result<usize> {
    #[cfg(debug_assertions)]
    println!("Writing: FFFFx\\n");
    port.write(b"FFFFx\n")
}

fn read_from_port(port: &mut Box<dyn SerialPort>, num_bytes: usize) -> io::Result<Vec<u8>> {
    std::thread::sleep(Duration::from_millis(10));
    let mut serial_buf: Vec<u8> = vec![0; num_bytes * 2];

    // Attempt to read from the port
    match port.read(serial_buf.as_mut_slice()) {
        Ok(bytes_read) => {
            // Resize the buffer to the actual number of bytes read
            serial_buf.truncate(bytes_read);
            #[cfg(debug_assertions)]
            println!(
                "Read {} bytes: {:#?}",
                num_bytes,
                strip_control_squences(&hex_to_ascii(&serial_buf))
            );
            Ok(serial_buf)
        }
        Err(e) => {
            eprintln!("Error reading from port: {}", e);
            Err(e)
        }
    }
}
