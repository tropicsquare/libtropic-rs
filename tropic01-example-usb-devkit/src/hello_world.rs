use rand_core::OsRng;
use tropic01::Tropic01;
use tropic01::X25519Dalek;
use tropic01::keys::SH0PRIV_PROD0;
use tropic01::keys::SH0PUB_PROD0;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use crate::usb_dongle::UsbDongle;

const PING_MSG: &[u8] = b"This is Hello World message from TROPIC01!!";

pub fn run(device_path: &str) -> Result<(), anyhow::Error> {
    env_logger::init();

    let dongle = UsbDongle::new(device_path, 115_200)?;
    let mut tropic01 = Tropic01::new(dongle);

    println!("======================================");
    println!("==== TROPIC01 Hello World Example ====");
    println!("======================================");

    // Reboot to ensure chip is running Application Firmware (not in Startup Mode).
    print!("Sending reboot request...");
    tropic01.startup_req(tropic01::StartupReq::Reboot)?;
    println!("OK");

    print!("Starting Secure Session with key slot 0...");
    let csprng = OsRng;
    let ehpriv = StaticSecret::random_from_rng(csprng);
    let ehpub = PublicKey::from(&ehpriv);
    let shpub = SH0PUB_PROD0.into();
    let shpriv = SH0PRIV_PROD0.into();
    let mut session = tropic01
        .session_start(&X25519Dalek, shpub, shpriv, ehpub, ehpriv, 0)
        .map_err(|(_, e)| e)?;
    println!("OK");

    println!("Sending Ping command...");
    println!(
        "\t--> Message sent to TROPIC01: '{}'",
        std::str::from_utf8(PING_MSG).expect("PING_MSG is valid UTF-8")
    );
    let res = session.ping(PING_MSG)?;
    println!(
        "\t<-- Message received from TROPIC01: '{}'",
        std::str::from_utf8(res).expect("ping response is valid UTF-8")
    );

    print!("Aborting Secure Session...");
    let _tropic01 = session.session_abort().map_err(|(_, e)| e)?;
    println!("OK");

    Ok(())
}
