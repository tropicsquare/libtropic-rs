#[cfg(test)]
mod tests {
    use super::super::{Command, get_random_bytes::GetRandomBytesCommand};

    #[test]
    fn test_get_random_bytes_32() {
        let cmd = GetRandomBytesCommand { n_bytes: 32 };
        let bytes = cmd.as_bytes();

        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes[0], 0x50);
        assert_eq!(bytes[1], 32);
    }

    #[test]
    fn test_get_random_bytes_1() {
        let cmd = GetRandomBytesCommand { n_bytes: 1 };
        let bytes = cmd.as_bytes();

        assert_eq!(bytes, vec![0x50, 0x01]);
    }

    #[test]
    fn test_get_random_bytes_255() {
        let cmd = GetRandomBytesCommand { n_bytes: 255 };
        let bytes = cmd.as_bytes();

        assert_eq!(bytes, vec![0x50, 0xff]);
    }
}
