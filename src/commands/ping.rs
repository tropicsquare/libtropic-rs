use crate::{checksum::crc16, commands::Command};

const CMD_ID: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingCommand {
    pub data: Vec<u8>,
}

impl Command for PingCommand {
    fn as_bytes(&self) -> Vec<u8> {
        if self.data.len() > 4096 {
            panic!("Ping command data must not exceed 4095 bytes in length.")
        }

        let mut bytes = vec![CMD_ID]; // reqid and reqlen

        bytes.extend(&self.data); // reqdata

        bytes
    }
}
