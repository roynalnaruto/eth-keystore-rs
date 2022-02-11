use eth_keystore::{decrypt_key, encrypt_key, new};
use hex::FromHex;
use std::path::Path;

mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let file = Path::new("./target/test_new.json");
        let mut rng = rand::thread_rng();
        let (secret, _uuid) = new(&file, &mut rng, "thebestrandompassword").unwrap();

        assert_eq!(
            decrypt_key(&file, "thebestrandompassword").unwrap(),
            secret
        );
        assert!(decrypt_key(&file, "notthebestrandompassword").is_err());
        assert!(std::fs::remove_file(&file).is_ok());
    }

    #[test]
    fn test_decrypt_pbkdf2() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-pbkdf2.json");
        assert_eq!(decrypt_key(&keypath, "testpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "wrongtestpassword").is_err());
    }

    #[test]
    fn test_decrypt_scrypt() {
        let secret =
            Vec::from_hex("80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-scrypt.json");
        assert_eq!(decrypt_key(&keypath, "grOQ8QDnGHvpYJf").unwrap(), secret);
        assert!(decrypt_key(&keypath, "thisisnotrandom").is_err());
    }

    #[test]
    fn test_encrypt_decrypt_key() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let file = Path::new("./target/test_encrypt_decrypt_key.json");
        let mut rng = rand::thread_rng();
        let _uuid = encrypt_key(&file, &mut rng, &secret, "newpassword").unwrap();

        assert_eq!(decrypt_key(&file, "newpassword").unwrap(), secret);
        assert!(decrypt_key(&file, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&file).is_ok());
    }
}
