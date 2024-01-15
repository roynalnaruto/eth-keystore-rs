use hex::FromHex;
use std::path::Path;

mod tests {
    use rand::prelude::ThreadRng;
    use rand::RngCore;
    use eth_keystore::{decrypt_key_v4, encrypt_key_v4};
    use eth_keystore::{decrypt_key_v3, encrypt_key_v3};
    use super::*;

    fn generate_priv_key(rng: &mut ThreadRng) -> Vec<u8> {
        let mut private_key = vec![0u8; 32];
        rng.fill_bytes(private_key.as_mut_slice());
        private_key
    }

    #[test]
    fn test_keystore_v3_without_name_should_return_priv_key() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let password = "thebestrandompassword";
        let priv_key = generate_priv_key(&mut rng);

        let id = encrypt_key_v3(&dir, &mut rng, priv_key.clone(), password, None).unwrap();

        let keypath = dir.join(&id);
        assert_eq!(
            decrypt_key_v3(&keypath, password).unwrap(),
            priv_key
        );
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn test_keystore_v3_with_name_should_return_priv_key() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let password = "thebestrandompassword";
        let name = "my_keystore_v3";
        let priv_key = generate_priv_key(&mut rng);

        let id = encrypt_key_v3(&dir, &mut rng, priv_key.clone(), password, Some(name)).unwrap();

        let keypath = dir.join(&id);
        assert_eq!(
            decrypt_key_v3(&keypath, password).unwrap(),
            priv_key
        );
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn test_keystore_v3_with_bad_password_should_return_err() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let password = "thebestrandompassword";
        let priv_key = generate_priv_key(&mut rng);

        let id = encrypt_key_v3(&dir, &mut rng, priv_key.clone(), password, None).unwrap();

        let keypath = dir.join(&id);
        assert!(
            decrypt_key_v3(&keypath, "wrongpassword").is_err()
        );
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_keystore_v3_decrypt_pbkdf2() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-pbkdf2.json");
        assert_eq!(decrypt_key_v3(&keypath, "testpassword").unwrap(), secret);
        assert!(decrypt_key_v3(&keypath, "wrongtestpassword").is_err());
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_keystore_v3_decrypt_scrypt() {
        let secret =
            Vec::from_hex("80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-scrypt.json");
        assert_eq!(decrypt_key_v3(&keypath, "grOQ8QDnGHvpYJf").unwrap(), secret);
        assert!(decrypt_key_v3(&keypath, "thisisnotrandom").is_err());
    }

    #[test]
    fn test_keystore_v4_without_name_should_return_priv_key() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let password = "thebestrandompassword";
        let priv_key = generate_priv_key(&mut rng);

        let id = encrypt_key_v4(&dir, &mut rng, priv_key.clone(), password, None).unwrap();

        let keypath = dir.join(&id);
        assert_eq!(
            decrypt_key_v4(&keypath, password).unwrap(),
            priv_key
        );
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn test_keystore_v4_with_name_should_return_priv_key() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let password = "thebestrandompassword";
        let name = "my_keystore_v4";
        let priv_key = generate_priv_key(&mut rng);

        let id = encrypt_key_v4(&dir, &mut rng, priv_key.clone(), password, Some(name)).unwrap();

        let keypath = dir.join(&id);
        assert_eq!(
            decrypt_key_v4(&keypath, password).unwrap(),
            priv_key
        );
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn test_keystore_v4_with_bad_password_should_return_err() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let password = "thebestrandompassword";
        let priv_key = generate_priv_key(&mut rng);

        let id = encrypt_key_v3(&dir, &mut rng, priv_key.clone(), password, None).unwrap();

        let keypath = dir.join(&id);
        assert!(
            decrypt_key_v4(&keypath, "wrongpassword").is_err()
        );
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

}
