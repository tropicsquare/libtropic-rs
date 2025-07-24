## Build binary

To build a cross-platform binary for Raspberry Pi use [Cross](https://github.com/cross-rs/cross)

```bash
cross build --release --target aarch64-unknown-linux-gnu
```

## Copy binary to device and run it

Run this on your host to build, copy to the Raspberry Pi and then run on the Raspberry Pi.

```bash
cross build --release --target aarch64-unknown-linux-gnu \
  && scp target/aarch64-unknown-linux-gnu/release/tropic01-example-rpi root@<your-raspberry-pi-ip>:/tmp/ \
  && ssh -t root@<your-raspberry-pi-ip> "cd /tmp; RUST_LOG=debug ./tropic01-example-rpi"
```

## Modify device tree, to include all three chip select pins supported including timing

The CS pin needs to be configured in the SPI device and via a jumper on the Raspberry Pi shield. The utilties provided by Tropic Square use GPIO 25 as CS2. Also the chip seems to require specific timing configuration. A device tree overlay is needed to configure this.

### Compile .dts file to .dtbo

Copy the `tropic_spi_overlay.dts` to the /tmp folder of the raspberry pi (adjust user and ip):

```bash
scp tropic_spi_overlay.dts root@<your-raspberry-pi-ip>:/tmp/
```

Then run this on the Raspberry Pi to compile and move the overlay:

```bash
cd /tmp
dtc -O dtb -o tropic_spi_overlay.dtbo tropic_spi_overlay.dts
mv tropic_spi_overlay.dtbo /boot/firmware/overlays/
```

Make sure this entry is in `/boot/firmware/config.txt`

```
# Configure Tropic spi timing
dtoverlay=tropic_spi_overlay
```
