## TROPIC01 USB Devkit Example

Demo app for the TROPIC01 secure chip using the TS1302 USB devkit (USB-to-SPI bridge).

The USB devkit presents as a serial port (e.g. `/dev/ttyACM0` on Linux, `/dev/tty.usbmodem*` on macOS) and proxies SPI transactions to the secure element using an ASCII hex protocol over UART at 115200 baud.

## Build

```bash
cargo build --release -p tropic01-example-usb-devkit
```

## Run

Connect the USB devkit and run one of the available commands:

```bash
cargo run --release -p tropic01-example-usb-devkit -- <command> [device_path]
```

The device path defaults to `/dev/ttyACM0` if not specified. Enable debug logging with `RUST_LOG`:

```bash
RUST_LOG=debug cargo run --release -p tropic01-example-usb-devkit -- <command> /dev/ttyACM0
```

## Commands

### `hello_world`

Establishes a secure session with TROPIC01 and sends a Ping message:

1. Reboot to Application Firmware
2. Start secure session (X25519 key exchange, pairing key slot 0)
3. Send and receive a Ping message
4. Abort session

```bash
cargo run --release -p tropic01-example-usb-devkit -- hello_world /dev/ttyACM0
```

### `identify_chip`

Reads and displays chip identification data:

- RISC-V and SPECT firmware versions
- RISC-V bootloader version (via maintenance reboot)
- Firmware bank headers (FW1, FW2, SPECT1, SPECT2)
- Full chip ID

```bash
cargo run --release -p tropic01-example-usb-devkit -- identify_chip /dev/ttyACM0
```

### `full_chain_verification`

Dumps the X.509 certificate chain from the chip to DER files:

- `t01_ese_cert.der` — device (eSE) certificate
- `t01_xxxx_ca_cert.der` — intermediate CA certificate
- `t01_ca_cert.der` — TROPIC01 CA certificate
- `tropicsquare_root_ca_cert.der` — Tropic Square root CA certificate

```bash
cargo run --release -p tropic01-example-usb-devkit -- full_chain_verification /dev/ttyACM0 [output_dir]
```

The output directory defaults to the current directory if not specified.

### `ecc_eddsa`

Demonstrates ECC key generation and EdDSA signing on TROPIC01:

1. Start secure session
2. Generate ECC key pair (P256, slot 0)
3. Sign a SHA-256 hash and verify the signature
4. Sign a raw message (4092 bytes) and verify the signature
5. Abort session

```bash
cargo run --release -p tropic01-example-usb-devkit -- ecc_eddsa /dev/ttyACM0
```
