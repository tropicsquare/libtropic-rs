use tropic01::BankId;
use tropic01::StartupReq;
use tropic01::Tropic01;

use crate::usb_dongle::UsbDongle;

pub fn run(device_path: &str) -> Result<(), anyhow::Error> {
    env_logger::init();

    let dongle = UsbDongle::new(device_path, 115_200)?;
    let mut tropic01 = Tropic01::new(dongle);

    println!("==============================================");
    println!("==== TROPIC01 Chip Identification Example ====");
    println!("==============================================");

    // Reboot to ensure chip is running Application Firmware (not in Startup Mode).
    print!("Sending reboot request...");
    tropic01.startup_req(StartupReq::Reboot)?;
    println!("OK");

    println!("Reading data from chip...");

    let fw_ver = tropic01.get_info_riscv_fw_ver()?;
    println!(
        "  RISC-V FW version: {:X}.{:X}.{:X} (.{:X})",
        fw_ver[3], fw_ver[2], fw_ver[1], fw_ver[0]
    );

    let fw_ver = tropic01.get_info_spect_fw_ver()?;
    println!(
        "  SPECT FW version: {:X}.{:X}.{:X} (.{:X})",
        fw_ver[3], fw_ver[2], fw_ver[1], fw_ver[0]
    );

    // Maintenance reboot to access bootloader version and FW bank headers.
    print!("Sending maintenance reboot request...");
    tropic01.startup_req(StartupReq::MaintenanceReboot)?;
    println!("OK");

    println!("Reading data from chip...");

    let fw_ver = tropic01.get_info_riscv_fw_ver()?;
    println!(
        "  RISC-V bootloader version: {:X}.{:X}.{:X} (.{:X})",
        fw_ver[3] & 0x7f,
        fw_ver[2],
        fw_ver[1],
        fw_ver[0]
    );

    println!("Firmware bank headers:");
    for (name, bank_id) in [
        ("RiscvFw1", BankId::RiscvFw1 as u8),
        ("RiscvFw2", BankId::RiscvFw2 as u8),
        ("SpectFw1", BankId::SpectFw1 as u8),
        ("SpectFw2", BankId::SpectFw2 as u8),
    ] {
        let header = tropic01.get_info_fw_bank(bank_id)?;
        println!("  {name}: {header:02x?}");
    }

    println!("---------------------------------------------------------");
    println!("Chip ID data:");
    let chip_id = tropic01.get_info_chip_id()?;
    println!("  {chip_id:02x?}");
    println!("---------------------------------------------------------");

    // Reboot back to Application Firmware.
    print!("Sending reboot request...");
    tropic01.startup_req(StartupReq::Reboot)?;
    println!("OK");

    Ok(())
}
