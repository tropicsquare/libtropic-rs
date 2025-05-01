# libtropic-rs playground

This branch is just for storing progress and will not be too similar to what `libtropic-rs` will become.


## Showcase

```Rust
let resp_obj_bytes = send_frame_and_get_response(
    &mut port,
    HandshakeReqFrame {
        data: handshake_req::ReqData {
            ephemeral_public_key: *host_public.as_bytes(),
            pairing_key_slot: handshake_req::pairing_key_slotIndex::Zero,
        },
    },
    Duration::from_millis(150),
);

let resp_ob = strip_control_squences(&hex_to_ascii(&resp_obj_bytes));

println!("Chip ephemeral key + auth tag: {:#?}", resp_ob); // e.g.: 51700ACFB6FB146E027BC64A77DFFBEE106D16E511576615
```

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

- [ ] Archive history and clean main branch so we get a fresh start


## How to empty the repo history before publication

```bash
git checkout main
git checkout --orphan new-main
git rm -rf .
git commit --allow-empty -m "Init"
git branch -M new-main main
git push origin main --force
```