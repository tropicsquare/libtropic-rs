# libtropic-rs playground

This branch is just for storing progress and will not be too similar to what `libtropic-rs` will become.

## Plan

- [x] Get comms up and running
- [x] Send any frame and get a response

### General Frames

- [x] Get the same CRC checksums as libtropic
- [ ] Think up some cool trait for frames
- [ ] Think up a communication procedure that will work for any l2/l3 frame

### Get_Info_Req (poc)

- [x] Proof of concept with raw bytes
- [x] Read the chip_id
- [x] Read the riscv fw version
- [x] Read the spect fw version
- [x] Read the X.509 cert ~ Marked as complete but I just got all the 29 chunks, of which the last ones are just 0xff repeating

### Far in the future but here go some ideas

- [ ] Protocol trait for connections
- [ ] SPI connection
- [ ] Write tests
