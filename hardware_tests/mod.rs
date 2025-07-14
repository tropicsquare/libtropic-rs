use libtropic_rs::*;
use std::time::Duration;

// Expected values from C library regression test
const EXPECTED_CHIP_ID_HEX: &str = "00000001000000000000000000000000000000000000000000000000000000000000000001000000054400000000ffffffffffff01f00f000544545354303103002800080b54524f50494330312d4553ffffffff000100000000ffff000100000000ffffffffffffffffffffffffffffffffffffffffffffffffffffb8010300";
const EXPECTED_RISCV_FW_VERSION_HEX: &str = "00020100";

#[test]
fn test_chip_info() {
    let mut port = serialport::new("/dev/cu.usbmodem4982328A384B1", 115_200)
        .timeout(Duration::from_millis(10))
        .open()
        .expect("Failed to open port");

    let chip_id_bytes = send_frame_and_get_response(
        &mut port,
        frames::get_info_req::GetInfoReqFrame {
            data: frames::get_info_req::ReqData::ChipID,
        },
        Duration::from_millis(150),
    );

    let chip_id_hex = bytes_to_hex_string(&chip_id_bytes);

    println!("Expected Chip ID: {}", EXPECTED_CHIP_ID_HEX);
    println!("Actual Chip ID:   {}", chip_id_hex);

    assert_eq!(
        chip_id_hex.to_lowercase(),
        EXPECTED_CHIP_ID_HEX.to_lowercase(),
        "Chip ID does not match expected value"
    );

    let riscv_fw_bytes = send_frame_and_get_response(
        &mut port,
        frames::get_info_req::GetInfoReqFrame {
            data: frames::get_info_req::ReqData::RiscvFwVersion,
        },
        Duration::from_millis(150),
    );

    let riscv_fw_hex = bytes_to_hex_string(&riscv_fw_bytes);

    println!(
        "Expected RISC-V FW Version: {}",
        EXPECTED_RISCV_FW_VERSION_HEX
    );
    println!("Actual RISC-V FW Version:   {}", riscv_fw_hex);

    assert_eq!(
        riscv_fw_hex.to_lowercase(),
        EXPECTED_RISCV_FW_VERSION_HEX.to_lowercase(),
        "RISC-V firmware version does not match expected value"
    );
}
