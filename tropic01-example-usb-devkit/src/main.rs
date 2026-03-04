mod ecc_eddsa;
mod full_chain_verification;
mod hello_world;
mod identify_chip;
mod usb_dongle;

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = std::env::args().collect();

    let usage = || {
        eprintln!(
                "Usage: {} <command> [device_path]\n\nCommands:\n  hello_world              \
                 Session + ping\n  identify_chip            Read chip ID, FW versions, bank \
                 headers\n  full_chain_verification  Dump X.509 certificate chain to DER files\n  \
                 ecc_eddsa                ECC key generation + EdDSA signing\n\ndevice_path \
                 defaults to /dev/ttyACM0",
                args[0]
            );
    };

    let command = match args.get(1) {
        Some(cmd) => cmd.as_str(),
        None => {
            usage();
            return Err(anyhow::anyhow!("missing command"));
        },
    };

    let device_path = args.get(2).map_or("/dev/ttyACM0", |s| s.as_str());

    match command {
        "hello_world" => hello_world::run(device_path),
        "ecc_eddsa" => ecc_eddsa::run(device_path),
        "identify_chip" => identify_chip::run(device_path),
        "full_chain_verification" => {
            let output_dir = args
                .get(3)
                .map_or_else(|| std::path::PathBuf::from("."), std::path::PathBuf::from);
            full_chain_verification::run(device_path, &output_dir)
        },
        _ => {
            usage();
            Err(anyhow::anyhow!("unknown command: {command}"))
        },
    }
}
