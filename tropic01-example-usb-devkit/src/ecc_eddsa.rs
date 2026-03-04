use ed25519_dalek::Signature;
use ed25519_dalek::VerifyingKey;
use rand_core::OsRng;
use sha2::Digest as _;
use tropic01::EccCurve;
use tropic01::Tropic01;
use tropic01::X25519Dalek;
use tropic01::keys::SH0PRIV_PROD0;
use tropic01::keys::SH0PUB_PROD0;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use crate::usb_dongle::UsbDongle;

pub fn run(device_path: &str) -> Result<(), anyhow::Error> {
    env_logger::init();

    let dongle = UsbDongle::new(device_path, 115_200)?;
    let mut tropic01 = Tropic01::new(dongle);

    println!("===========================================");
    println!("==== TROPIC01 ECC + EdDSA Sign Example ====");
    println!("===========================================");

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

    // Erase any existing key in slot 0 before generating a new one.
    let key_slot = 0.into();
    print!("Erasing ECC slot 0...");
    session.ecc_key_erase(key_slot)?;
    println!("OK");

    // Generate ECC key pair on the chip (Ed25519, slot 0).
    print!("Generating ECC key (Ed25519, slot 0)...");
    session.ecc_key_generate(key_slot, EccCurve::Ed25519)?;
    println!("OK");

    // Read the public key back.
    let res = session.ecc_key_read(key_slot)?;
    let public_key =
        VerifyingKey::from_bytes(res.pub_key().try_into()?).expect("public key to be valid");
    println!("Public key: {:02x?}", res.pub_key());

    // EdDSA signature of a SHA-256 hash.
    let msg = "hello tropic";
    let mut hasher = sha2::Sha256::new();
    hasher.update(msg);
    let hash: [u8; 32] = hasher.finalize().into();

    print!("Signing SHA-256 hash of '{msg}'...");
    let signature = session.eddsa_sign(key_slot, &hash)?;
    println!("OK");
    println!("  Signature: {signature:02x?}");

    public_key
        .verify_strict(&hash, &Signature::from_bytes(signature))
        .expect("hash signature to verify");
    println!("  Verification: OK");

    // EdDSA signature of a raw (long) message.
    let msg = "hello tropic".repeat(341);
    let msg = msg.as_bytes();

    print!("Signing raw message ({} bytes)...", msg.len());
    let signature = session.eddsa_sign(key_slot, msg)?;
    println!("OK");
    println!("  Signature: {signature:02x?}");

    public_key
        .verify_strict(msg, &Signature::from_bytes(signature))
        .expect("raw message signature to verify");
    println!("  Verification: OK");

    print!("Aborting Secure Session...");
    let _tropic01 = session.session_abort().map_err(|(_, e)| e)?;
    println!("OK");

    Ok(())
}
