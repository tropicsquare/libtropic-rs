pub mod get_random_bytes;
pub mod get_random_bytes_tests;
pub mod ping;
pub mod ping_tests;

pub trait Command {
    fn as_bytes(&self) -> Vec<u8>;
}
