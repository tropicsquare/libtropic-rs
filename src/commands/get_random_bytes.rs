use crate::commands::Command;

const CMD_ID: u8 = 0x50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetRandomBytesCommand {
    pub n_bytes: u8,
}

impl Command for GetRandomBytesCommand {
    fn as_bytes(&self) -> Vec<u8> {
        // no need to check for the limits, since there are type limits on u8 and the chip will return 0 random bytes just fine

        let mut bytes = vec![CMD_ID];
        bytes.push(self.n_bytes);

        bytes
    }
}
