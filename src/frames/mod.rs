pub mod get_info_req;
pub mod get_info_req_tests;
pub mod handshake_req;
pub mod handshake_req_tests;

use super::checksum::*;

pub trait Frame {
    fn as_bytes(&self) -> Vec<u8>;
    fn from_bytes(data: &[u8]) -> Result<Self, String>
    where
        Self: Sized;
}
