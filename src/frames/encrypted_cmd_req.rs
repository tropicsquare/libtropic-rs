use super::*;

const REQ_ID: u8 = 0x04;
// REQ_LEN is variable (0x01 - 0xfc) / 1 - 252 bytes, because 256 - req id (1) - req len (1) - checksum (2)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReqData {
    pub encryped_command: Vec<u8>,
}

impl ReqData {
    /// Serialize the payload to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        println!("{:#?}", self.encryped_command.len());
        if self.encryped_command.len() > 252 {
            panic!("Payload too large for one frame, you need to slice it into chunks <= 252 bytes")
        }

        self.encryped_command.clone()
    }

    /// Deserialize bytes into a `Payload`
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            encryped_command: bytes.to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedCmdReq {
    pub data: ReqData,
}

impl Frame for EncryptedCmdReq {
    fn as_bytes(&self) -> Vec<u8> {
        let command_bytes = self.data.to_bytes();

        let mut bytes = vec![REQ_ID, command_bytes.len() as u8]; // reqid and reqlen
        bytes.extend(command_bytes); // reqdata

        let crc = crc16(&bytes);
        bytes.extend(&crc); // crc16

        bytes
    }

    fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() > 256 {
            return Err("Invalid frame length".into());
        }

        let expected_crc = crc16(&data[0..4]);
        let received_crc = [data[4], data[5]];

        if expected_crc != received_crc {
            return Err("CRC mismatch".into());
        }

        let req_data = ReqData::from_bytes(&data[2..])?;
        Ok(EncryptedCmdReq { data: req_data })
    }
}
