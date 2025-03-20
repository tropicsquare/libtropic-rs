# Serial MITM

This is how to capture the full comms between lt-util and the usb tropic01 on mac:

1. Set up socat (install from brew.sh first) to create a virtual serial port and forward it to the tropic01 board:

`socat -d -d -v PTY,link=/tmp/virtual_serial,raw,echo=1,icanon=1 OPEN:/dev/cu.usbmodem4982328A384B1,raw`

2. Configure `lt-util` to use the virtual serial port `/tmp/virtual_serial` in `libtropic-util/libtropic/hal/port/unix/lt_port_unix_usb_dongle.c`

3. Run `lt-util` and observe the output.
