use super::*;

const REQ_ID: u8 = 0x02;
const REQ_LEN: u8 = 0x21; // 33 bytes

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum pairing_key_slotIndex {
    Zero = 0x00,
    One = 0x01,
    Two = 0x02,
    Three = 0x03,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReqData {
    pub ephemeral_public_key: [u8; 32],
    pub pairing_key_slot: pairing_key_slotIndex,
}

impl ReqData {
    /// Serialize the payload to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33);
        bytes.extend_from_slice(&self.ephemeral_public_key);
        bytes.push(self.pairing_key_slot as u8);
        bytes
    }

    /// Deserialize bytes into a `Payload`
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 33 {
            return Err("Invalid byte length".to_string());
        }

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[..32]);

        let slot = match bytes[32] {
            0x00 => pairing_key_slotIndex::Zero,
            0x01 => pairing_key_slotIndex::One,
            0x02 => pairing_key_slotIndex::Two,
            0x03 => pairing_key_slotIndex::Three,
            _ => return Err("Invalid pairing_key_slotIndex".to_string()),
        };

        Ok(Self {
            ephemeral_public_key: public_key,
            pairing_key_slot: slot,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeReqFrame {
    pub data: ReqData,
}

impl Frame for HandshakeReqFrame {
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

        let req_data = ReqData::from_bytes(&data[2..35])?;
        Ok(HandshakeReqFrame { data: req_data })
    }
}
