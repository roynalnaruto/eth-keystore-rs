use eth_keystore::decrypt_key;
use hex::FromHex;
use std::path::Path;

mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_new() {
        todo!();
    }

    #[test]
    fn test_decrypt_pbkdf2() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-pbkdf2.json");
        assert_eq!(decrypt_key(&keypath, "testpassword"), Ok(secret.clone()));
    }

    #[test]
    fn test_decrypt_scrypt() {
        let secret =
            Vec::from_hex("80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-scrypt.json");
        assert_eq!(decrypt_key(&keypath, "grOQ8QDnGHvpYJf"), Ok(secret));
    }

    #[test]
    #[ignore]
    fn test_encrypt_key() {
        todo!();
    }
}
