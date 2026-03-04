use std::fs;
use std::path::Path;

use tropic01::Tropic01;

use crate::usb_dongle::UsbDongle;

const CERT_NAMES: [&str; 4] = [
    "t01_ese_cert.der",
    "t01_xxxx_ca_cert.der",
    "t01_ca_cert.der",
    "tropicsquare_root_ca_cert.der",
];

pub fn run(device_path: &str, output_dir: &Path) -> Result<(), anyhow::Error> {
    env_logger::init();

    let dongle = UsbDongle::new(device_path, 115_200)?;
    let mut tropic01 = Tropic01::new(dongle);

    println!("====================================================");
    println!("==== TROPIC01 Certificate Chain Dumping Utility =====");
    println!("====================================================");

    println!("Reading certificates from TROPIC01...");
    let cert_store = tropic01.get_info_cert_store()?;

    println!("Writing certificates to files...");
    for (i, name) in CERT_NAMES.iter().enumerate() {
        let cert = cert_store
            .cert(i)
            .ok_or_else(|| anyhow::anyhow!("Error: Certificate {i} is empty!"))?;

        let path = output_dir.join(name);
        fs::write(&path, cert)?;
        println!("  {}: {} bytes", path.display(), cert.len());
    }

    println!("Certificates dumped successfully!");
    Ok(())
}
