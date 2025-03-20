use super::*;

const REQ_ID: u8 = 0x01;
const REQ_LEN: u8 = 0x02;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReqData {
    X509Certificate { chunk: u8 } = 0x00,
    ChipID = 0x01,
    RiscvFwVersion = 0x02,
    SpectFwVersion = 0x04,
}

impl ReqData {
    /// Serialize the payload to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            // limit the chunk number to 29 //? why
            &ReqData::X509Certificate { chunk } => vec![0x01, chunk],
            &ReqData::ChipID => vec![0x01, 0x00],
            &ReqData::RiscvFwVersion => vec![0x02, 0x00],
            &ReqData::SpectFwVersion => vec![0x04, 0x00],
        }
    }

    /// Deserialize bytes into a `Payload`
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // if !verify_checksum(bytes) {
        //     Err("Invalid checksum".into())
        // }

        match bytes {
            [0x00, chunk] if *chunk <= 0x1D => Ok(ReqData::X509Certificate { chunk: *chunk }),
            [0x01, 0x00] => Ok(ReqData::ChipID),
            [0x02, 0x00] => Ok(ReqData::RiscvFwVersion),
            [0x04, 0x00] => Ok(ReqData::SpectFwVersion),
            _ => Err("Invalid request data".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetInfoReqFrame {
    pub data: ReqData,
}

impl Frame for GetInfoReqFrame {
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![REQ_ID, REQ_LEN]; // reqid and reqlen
        bytes.extend(self.data.to_bytes()); // reqdata

        let crc = crc16(&bytes);
        bytes.extend(&crc); // crc16

        bytes
    }

    fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() != 6 {
            return Err("Invalid frame length".into());
        }

        let expected_crc = crc16(&data[0..4]);
        let received_crc = [data[4], data[5]];

        if expected_crc != received_crc {
            return Err("CRC mismatch".into());
        }

        let req_data = ReqData::from_bytes(&data[2..4])?;
        Ok(GetInfoReqFrame { data: req_data })
    }
}
