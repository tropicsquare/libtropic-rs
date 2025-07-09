#[cfg(test)]

mod unit {
    use crate::commands::{Command, ping::PingCommand};

    #[test]
    fn works() {
        let ping_cmd = PingCommand {
            data: vec![0xff, 0xdd],
        };

        assert_eq!(ping_cmd.as_bytes(), vec![0x01, 0xff, 0xdd])
    }
}
