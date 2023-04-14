use eth_keystore::{decrypt_key, encrypt_key};
use hex::FromHex;
use std::path::Path;

mod tests {
    use super::*;

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_decrypt_pbkdf2() {
        // Test vec from: https://eips.ethereum.org/EIPS/eip-2335
        let secret =
            Vec::from_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();

        let encoded_pw = hex::decode("7465737470617373776f7264f09f9491").unwrap();
        let pw = String::from_utf8(encoded_pw).unwrap();
        let keypath = Path::new("./tests/test-keys/key-pbkdf2.json");
        assert_eq!(decrypt_key(&keypath, pw).unwrap(), secret);
        assert!(decrypt_key(&keypath, "wrongtestpassword").is_err());
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_decrypt_scrypt() {
        // Test vec from: https://eips.ethereum.org/EIPS/eip-2335
        let secret =
            Vec::from_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let encoded_pw = hex::decode("7465737470617373776f7264f09f9491").unwrap();
        let pw = String::from_utf8(encoded_pw).unwrap();
        let keypath = Path::new("./tests/test-keys/key-scrypt.json");
        assert_eq!(decrypt_key(&keypath, pw).unwrap(), secret);
        assert!(decrypt_key(&keypath, "thisisnotrandom").is_err());
    }

    #[test]
    fn test_encrypt_decrypt_key() {
        let secret =
            Vec::from_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let name = encrypt_key(&dir, &mut rng, &secret, "newpassword", None).unwrap();

        let keypath = dir.join(&name);
        assert_eq!(decrypt_key(&keypath, "newpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }
}
