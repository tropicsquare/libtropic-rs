use std::io::{self, Read, Write};
use std::{time::Duration, vec};

use frames::get_info_req::{GetInfoReqFrame, ReqData};
use serialport::SerialPort;

mod utils;
use utils::*;

mod frames;
use frames::*;

mod checksum;
mod checksum_tests;
use checksum::*;

fn main() -> io::Result<()> {
    let mut port = serialport::new("/dev/cu.usbmodem4982328A384B1", 115_200)
        .timeout(Duration::from_millis(10))
        .open()
        .expect("Failed to open port");

    let mut bytes: Vec<u8> = vec![];

    for cert_chunk in 0x00..=0x1D {
        set_cs_high(&mut port).unwrap_or_else(|_| panic!("Could not set CS; line: {}", line!()));
        read_from_port(&mut port, 3)
            .unwrap_or_else(|_| panic!("Could not read; line: {}", line!()));

        let frame = GetInfoReqFrame {
            data: ReqData::X509Certificate { chunk: cert_chunk },
        };

        let wrote_bytes = send_l2_frame(frame.as_bytes(), &mut port)
            .unwrap_or_else(|_| panic!("Could not write; line: {}", line!()));

        read_from_port(&mut port, wrote_bytes)
            .unwrap_or_else(|_| panic!("Could not read; line: {}", line!()));

        set_cs_high(&mut port).unwrap_or_else(|_| panic!("Could not set CS; line: {}", line!()));
        read_from_port(&mut port, 3)
            .unwrap_or_else(|_| panic!("Could not read; line: {}", line!()));

        send_response_request(&mut port)
            .unwrap_or_else(|_| panic!("Could not send response request; line: {}", line!()));

        read_from_port(&mut port, 4)
            .unwrap_or_else(|_| panic!("Could not read response size; line: {}", line!()));

        send_response_size_request(&mut port)
            .unwrap_or_else(|_| panic!("Could not send response size request; line: {}", line!()));

        let resp = read_from_port(&mut port, 8)
            .unwrap_or_else(|_| panic!("Could not read response size; line: {}", line!()));
        let resp_str = strip_control_squences(&hex_to_ascii(&resp));

        // for some reason, there is an extraneous 01 (ok) before the response len
        let resp_len = hex_str_to_dec(&resp_str[2..])
            .unwrap_or_else(|_| panic!("Could not convert from hex str to dec; line: {}", line!()));
        let _ = write_n_junk_bytes(&mut port, 128)
            .unwrap_or_else(|_| panic!("Could not write junk; line: {}", line!()));

        // add 2 bytes for crc
        let resp_obj_bytes = read_from_port(&mut port, resp_len + 2)
            .unwrap_or_else(|_| panic!("Could not read chip ID; line: {}", line!()));
        let resp_ob = strip_control_squences(&ascii_bytes_to_hex_to_ascii(resp_obj_bytes.to_vec()));
        println!("{:#?}", resp_ob);

        // if !verify_checksum(&resp_obj_bytes) {
        //     panic!();
        // }

        bytes.extend(ascii_bytes_to_bytes(&hex_to_ascii(&resp_obj_bytes[..resp_len])).unwrap());

        println!("{:#?}", bytes_to_ascii(&bytes));
    }

    Ok(())
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
    let mut f_string = "F".repeat(n);
    f_string.push_str("\n");

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
    let mut serial_buf: Vec<u8> = vec![0; num_bytes];

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
