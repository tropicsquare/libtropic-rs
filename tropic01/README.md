# TROPIC01 Rust driver

Platform agnostic `embedded-hal` driver for the TROPIC01 crypto chip.

## Current State

Most of the critical features are implemented. If you are missing a feature, please open an issue and/or MR.

- [ ] Bootloader API
  - [x] Get X509 Certificate
  - [x] Get Chip Id
  - [x] Resend request
  - [x] Startup request
  - [x] Get Log Request
  - [ ] Other Bootloader commands
- [ ] Application API
  - [x] Handshake request & secure session start
  - [x] Encrypted command request
  - [x] Sleep request
  - [ ] Abort encrypted session
  - [ ] L3 Commands
    - [x] Ping
    - [x] Get Random Value
    - [x] Ecc Key Generation
    - [x] Ecc Key Read
    - [x] EcDSA signatures
    - [x] EdDSA signatures
    - [ ] Other L3 commands
- [ ] Defmt support
- [x] Hardware handled CS pin
- [x] Software handled CS pin

## References

- [C implementation by Tropic Square](https://github.com/tropicsquare/libtropic/blob/master)
- [Datasheet and User API](https://github.com/tropicsquare/tropic01/tree/main/doc)


## License

See the [LICENSE.md](LICENSE.md) file in the root of this folder or consult license information at [Tropic Square website](http:/tropicsquare.com/license).
