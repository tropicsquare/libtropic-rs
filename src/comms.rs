use crate::checksum::verify_checksum;
use crate::frames::Frame;
use crate::{ascii_bytes_to_real_bytes, hex_str_to_dec, hex_to_ascii, strip_control_squences};
use serialport::SerialPort;
use std::io::{self, Read, Write};
use std::thread;
use std::{time::Duration, vec};

pub fn send_frame_and_get_response<T: Frame>(
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

pub fn send_frame_and_get_req_cont<T: Frame>(
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

pub fn get_next_response(
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

pub fn send_l2_frame(frame: Vec<u8>, port: &mut Box<dyn SerialPort>) -> io::Result<usize> {
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

pub fn write_n_junk_bytes(port: &mut Box<dyn SerialPort>, n: usize) -> io::Result<usize> {
    let mut f_string = "FF".repeat(n);
    f_string.push_str("x\n");

    #[cfg(debug_assertions)]
    println!("Writing {} junk bytes: {:#?}", n, f_string);
    port.write(f_string.as_bytes())
}

pub fn set_cs_high(port: &mut Box<dyn SerialPort>) -> io::Result<usize> {
    #[cfg(debug_assertions)]
    println!("Writing: CS=0\\n");
    port.write(b"CS=0\n")
}

pub fn send_response_request(port: &mut Box<dyn SerialPort>) -> io::Result<usize> {
    #[cfg(debug_assertions)]
    println!("Writing: AAx\\n");
    port.write(b"AAx\n")
}

pub fn send_response_size_request(port: &mut Box<dyn SerialPort>) -> io::Result<usize> {
    #[cfg(debug_assertions)]
    println!("Writing: FFFFx\\n");
    port.write(b"FFFFx\n")
}

pub fn read_from_port(port: &mut Box<dyn SerialPort>, num_bytes: usize) -> io::Result<Vec<u8>> {
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
