use ed25519_dalek::Signature;
use ed25519_dalek::VerifyingKey;
use linux_embedded_hal::SpidevDevice;
use linux_embedded_hal::spidev::SpiModeFlags;
use linux_embedded_hal::spidev::SpidevOptions;
use rand_core::OsRng;
use sha2::Digest as _;
use tropic01::EccCurve;
use tropic01::Error;
use tropic01::Tropic01;
use tropic01::X25519Dalek;
use tropic01::keys::SH0PRIV;
use tropic01::keys::SH0PUB;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let mut spi_device = SpidevDevice::open("/dev/spidev0.2")?;
    spi_device.configure(
        &SpidevOptions::new()
            .max_speed_hz(5_000_000)
            .mode(SpiModeFlags::SPI_MODE_0)
            .build(),
    )?;
    let mut tropic01 = Tropic01::new(spi_device)
    // Optionally, the driver can be setup with a cs pin:

        // .with_cs_pin(
        //     rppal::gpio::Gpio::new()?
        //         .get(25)?
        //         .into_output(),
        // )?
        ;

    let res = tropic01.get_info_chip_id()?;
    println!("ChipId: {res:x?}");
    let chip_id = res.to_vec();

    println!("Sleep");
    tropic01.sleep_req(tropic01::SleepReq::Sleep)?;

    let res = tropic01.get_info_cert()?;
    println!("Cert: {res:x?}");

    println!("Reboot");
    tropic01.startup_req(tropic01::StartupReq::Reboot)?;
    println!("Rebooted");

    let res = tropic01.get_info_chip_id()?;
    println!("ChipId after reboot: {res:x?}");
    assert_eq!(res, &chip_id);

    let csprng = OsRng;
    let ehpriv = StaticSecret::random_from_rng(csprng);
    let ehpub = PublicKey::from(&ehpriv);
    let shpub = SH0PUB.into();
    let shpriv = SH0PRIV.into();
    tropic01.session_start(&X25519Dalek, shpub, shpriv, ehpub, ehpriv, 0)?;

    let res = tropic01.get_random_value(6)?;
    println!("random value get: {res:x?}");

    let ping_data = b"";
    let res = tropic01.ping(ping_data)?;
    // Test empty data loopback
    assert_eq!(res, ping_data);

    let ping_data = [6; 4096];
    let res = tropic01.ping(&ping_data)?;
    // Test long data loopback
    assert_eq!(res, ping_data);

    let key_slot = 0.into();
    tropic01.ecc_key_generate(key_slot, EccCurve::P256)?;

    let res = tropic01.ecc_key_read(key_slot)?;
    println!("key read response: {res:x?}");

    let public_key =
        VerifyingKey::from_bytes(res.pub_key().try_into()?).expect("public key to be valid");

    // Signature of hash
    let msg = "hello tropic";
    let mut hasher = sha2::Sha256::new();
    hasher.update(msg);
    let hash: [u8; 32] = hasher.finalize().into();
    let signature = tropic01.eddsa_sign(key_slot, &hash)?;
    println!("signature of hash: {signature:x?}");
    public_key
        .verify_strict(&hash, &Signature::from_bytes(signature))
        .expect("signature to be verified");

    // Produce an unauthorized error to test nonce behavior
    if shpub.as_bytes() == &SH0PUB {
        assert!(matches!(
            tropic01.ecc_key_generate(3.into(), EccCurve::P256),
            Err(Error::Unauthorized)
        ));
    }

    // Signature of raw message
    let msg = "hello tropic".repeat(341);
    let msg = msg.as_bytes();
    let signature = tropic01.eddsa_sign(key_slot, msg)?;
    println!("signature of long raw msg: {signature:x?}");
    public_key
        .verify_strict(msg, &Signature::from_bytes(signature))
        .expect("signature to be verified");

    Ok(())
}
