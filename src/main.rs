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

use x25519_dalek::{EphemeralSecret, PublicKey};

static DEV_PRIV_KEY_INDEX_0: [u8; 32] = [
    0xd0, 0x99, 0x92, 0xb1, 0xf1, 0x7a, 0xbc, 0x4d, 0xb9, 0x37, 0x17, 0x68, 0xa2, 0x7d, 0xa0, 0x5b,
    0x18, 0xfa, 0xb8, 0x56, 0x13, 0xa7, 0x84, 0x2c, 0xa6, 0x4c, 0x79, 0x10, 0xf2, 0x2e, 0x71, 0x6b,
];

static DEV_PUB_KEY_INDEX_0: [u8; 32] = [
    0xe7, 0xf7, 0x35, 0xba, 0x19, 0xa3, 0x3f, 0xd6, 0x73, 0x23, 0xab, 0x37, 0x26, 0x2d, 0xe5, 0x36,
    0x08, 0xca, 0x57, 0x85, 0x76, 0x53, 0x43, 0x52, 0xe1, 0x8f, 0x64, 0xe6, 0x13, 0xd3, 0x8d, 0x54,
];

fn main() -> io::Result<()> {
    let mut port = serialport::new("/dev/cu.usbmodem4982328A384B1", 115_200)
        .timeout(Duration::from_millis(10))
        .open()
        .expect("Failed to open port");

    // let mut bytes: Vec<u8> = vec![];
    // for cert_chunk in 0x00..=0x1D {
    //     let resp_obj_bytes = send_frame_and_get_response(
    //         &mut port,
    //         GetInfoReqFrame {
    //             data: get_info_req::ReqData::X509Certificate { chunk: cert_chunk },
    //         },
    //         Duration::from_millis(100),
    //     );

    //     // this response seems to come with a crc, so the last two bytes are cut
    //     bytes.extend(resp_obj_bytes);

    //     println!("Got chunk: {:#?}", cert_chunk);
    // }

    // println!(
    //     "X.509 Cert: {:#?}",
    //     strip_control_squences(&bytes_to_ascii(&bytes))
    // );

    // let resp_obj_bytes = send_frame_and_get_response(
    //     &mut port,
    //     GetInfoReqFrame {
    //         data: get_info_req::ReqData::ChipID,
    //     },
    //     Duration::from_millis(150),
    // );

    // let resp_ob = strip_control_squences(&bytes_to_ascii(&resp_obj_bytes.to_vec()));

    // println!("Chip ID: {:#?}", resp_ob);

    // let resp_obj_bytes = send_frame_and_get_response(
    //     &mut port,
    //     GetInfoReqFrame {
    //         data: get_info_req::ReqData::RiscvFwVersion,
    //     },
    //     Duration::from_millis(150),
    // );

    // let resp_ob = strip_control_squences(&bytes_to_ascii(&resp_obj_bytes));

    // println!("Riscv Fw Version: {:#?}", resp_ob);

    // let resp_obj_bytes = send_frame_and_get_response(
    //     &mut port,
    //     GetInfoReqFrame {
    //         data: get_info_req::ReqData::SpectFwVersion,
    //     },
    //     Duration::from_millis(0),
    // );

    // let resp_ob = strip_control_squences(&bytes_to_ascii(&resp_obj_bytes));

    // println!("Spect Fw Version: {:#?}", resp_ob);

    let host_secret = EphemeralSecret::random();
    let host_public = PublicKey::from(&host_secret);

    let resp_obj_bytes = send_frame_and_get_response(
        &mut port,
        HandshakeReqFrame {
            data: handshake_req::ReqData {
                ephemeral_public_key: *host_public.as_bytes(),
                pairing_key_slot: handshake_req::pairing_key_slotIndex::Zero,
            },
        },
        Duration::from_millis(150),
    );

    let chip_ephemeral_key_bytes = resp_obj_bytes[..32.min(resp_obj_bytes.len())].to_vec();
    let auth_tag = resp_obj_bytes[..16.min(resp_obj_bytes.len())].to_vec();

    println!(
        "Chip ephemeral key: {:#?}",
        bytes_to_hex_string(&chip_ephemeral_key_bytes)
    );

    println!("Auth tag: {:#?}", bytes_to_hex_string(&auth_tag));

    let ephemeral_key_bytes_sized: [u8; 32] = chip_ephemeral_key_bytes
        .try_into()
        .unwrap_or_else(|_| panic!("Invalid length; line: {}", line!()));
    let chip_ephemeral_public_key = PublicKey::from(ephemeral_key_bytes_sized);

    let shared_secret = host_secret.diffie_hellman(&chip_ephemeral_public_key);

    println!(
        "Shared secret: {:#?}",
        bytes_to_hex_string(shared_secret.as_bytes())
    );

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
                num_bytes * 2,
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
