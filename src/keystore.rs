use hex::{FromHex, ToHex};
use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "geth-compat")]
use ethereum_types::H160 as Address;

#[derive(Debug, Deserialize, Serialize)]
/// This struct represents the deserialized form of an encrypted JSON keystore based on the
/// [Web3 Secret Storage Definition](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).
pub struct EthKeystoreV3 {
    #[cfg(feature = "geth-compat")]
    pub address: Address,

    pub crypto: CryptoJsonV3,
    pub id: Uuid,
    pub version: u8,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "crypto" part of an encrypted JSON keystore.
pub struct CryptoJsonV3 {
    pub cipher: String,
    pub cipherparams: CipherparamsJsonV3,
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub ciphertext: Vec<u8>,
    pub kdf: KdfType,
    pub kdfparams: KdfparamsType,
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub mac: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "cipherparams" part of an encrypted JSON keystore.
pub struct CipherparamsJsonV3 {
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub iv: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
/// This struct represents the deserialized form of an encrypted JSON keystore based on the
/// [eip-2335](https://eips.ethereum.org/EIPS/eip-2335).
pub struct EthKeystoreV4 {
    pub crypto: CryptoJsonV4,
    pub description: String,
    pub pubkey: String,
    pub path: String,
    pub uuid: String,
    pub version: u8,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "crypto" part of an encrypted JSON keystore.
pub struct CryptoJsonV4 {
    pub kdf: Kdf,
    pub checksum: Checksum,
    pub cipher: Cipher,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "crypto" part of an encrypted JSON keystore.
pub struct Kdf {
    pub function: KdfType,
    pub params: KdfparamsType,
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub message: Vec<u8>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
/// Types of key derivation functions supported by the Web3 Secret Storage EIP-2335.
pub enum KdfType {
    Pbkdf2,
    Scrypt,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
/// Defines the various parameters used in the supported KDFs.
pub enum KdfparamsType {
    Pbkdf2 {
        c: u32,
        dklen: u8,
        prf: String,
        #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
        salt: Vec<u8>,
    },
    Scrypt {
        dklen: u8,
        n: u32,
        r: u32,
        p: u32,
        #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
        salt: Vec<u8>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Checksum {
    pub function: HashFunction,
    pub params: ChecksumParams,
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub message: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChecksumParams {}

#[derive(Debug, Deserialize, Serialize)]
pub struct Cipher {
    pub function: String,
    pub params: CipherparamsJson,
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub message: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "cipherparams" part of an encrypted JSON keystore.
pub struct CipherparamsJson {
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub iv: Vec<u8>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
/// Types of key derivition functions supported by the Web3 Secret Storage.
pub enum HashFunction {
    Sha256,
}

fn buffer_to_hex<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
{
    serializer.serialize_str(&buffer.encode_hex::<String>())
}

fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "geth-compat")]
    #[test]
    fn deserialize_geth_compat_keystore_v3() {
        // Test vec from web3-secret-storage
        let data = r#"
        {
            "address": "00000398232e2064f896018496b4b44b3d62751f",
            "crypto": {
                "cipher": "aes-128-ctr",
                "ciphertext": "4f784cd629a7caf34b488e36fb96aad8a8f943a6ce31c7deab950c5e3a5b1c43",
                "cipherparams": {
                    "iv": "76f07196b3c94f25b8f34d869493f640"
                },
                "kdf": "scrypt",
                "kdfparams": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "1e7be4ce8351dd1710b0885438414b1748a81f1af510eda11e4d1f99c8d43975"
                },
                "mac": "5b5433575a2418c1c813337a88b4099baa2f534e5dabeba86979d538c1f594d8"
            },
            "id": "6c4485f3-3cc0-4081-848e-8bf489f2c262",
            "version": 3
        }"#;
        let keystore: EthKeystoreV3 = serde_json::from_str(data).unwrap();
        assert_eq!(
            keystore.address.as_bytes().to_vec(),
            hex::decode("00000398232e2064f896018496b4b44b3d62751f").unwrap()
        );
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_deserialize_pbkdf2_keystore_v3() {
        let data = r#"
        {
            "crypto" : {
                "cipher" : "aes-128-ctr",
                "cipherparams" : {
                    "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
                },
                "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
                "kdf" : "pbkdf2",
                "kdfparams" : {
                    "c" : 262144,
                    "dklen" : 32,
                    "prf" : "hmac-sha256",
                    "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
                },
                "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
            },
            "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
            "version" : 3
        }"#;
        let keystore: EthKeystoreV3 = serde_json::from_str(data).unwrap();
        assert_eq!(keystore.version, 3);
        assert_eq!(
            keystore.id,
            Uuid::parse_str("3198bc9c-6672-5ab3-d995-4942343ae5b6").unwrap()
        );
        assert_eq!(keystore.crypto.cipher, "aes-128-ctr");
        assert_eq!(
            keystore.crypto.cipherparams.iv,
            Vec::from_hex("6087dab2f9fdbbfaddc31a909735c1e6").unwrap()
        );
        assert_eq!(
            keystore.crypto.ciphertext,
            Vec::from_hex("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46")
                .unwrap()
        );
        assert_eq!(keystore.crypto.kdf, KdfType::Pbkdf2);
        assert_eq!(
            keystore.crypto.kdfparams,
            KdfparamsType::Pbkdf2 {
                c: 262144,
                dklen: 32,
                prf: String::from("hmac-sha256"),
                salt: Vec::from_hex(
                    "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
                )
                    .unwrap(),
            }
        );
        assert_eq!(
            keystore.crypto.mac,
            Vec::from_hex("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2")
                .unwrap()
        );
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_deserialize_scrypt_keystore_v3() {
        let data = r#"
        {
            "crypto" : {
                "cipher" : "aes-128-ctr",
                "cipherparams" : {
                    "iv" : "83dbcc02d8ccb40e466191a123791e0e"
                },
                "ciphertext" : "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
                "kdf" : "scrypt",
                "kdfparams" : {
                    "dklen" : 32,
                    "n" : 262144,
                    "p" : 8,
                    "r" : 1,
                    "salt" : "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
                },
                "mac" : "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
            },
            "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
            "version" : 3
        }"#;
        let keystore: EthKeystoreV3 = serde_json::from_str(data).unwrap();
        assert_eq!(keystore.version, 3);
        assert_eq!(
            keystore.id,
            Uuid::parse_str("3198bc9c-6672-5ab3-d995-4942343ae5b6").unwrap()
        );
        assert_eq!(keystore.crypto.cipher, "aes-128-ctr");
        assert_eq!(
            keystore.crypto.cipherparams.iv,
            Vec::from_hex("83dbcc02d8ccb40e466191a123791e0e").unwrap()
        );
        assert_eq!(
            keystore.crypto.ciphertext,
            Vec::from_hex("d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c")
                .unwrap()
        );
        assert_eq!(keystore.crypto.kdf, KdfType::Scrypt);
        assert_eq!(
            keystore.crypto.kdfparams,
            KdfparamsType::Scrypt {
                dklen: 32,
                n: 262144,
                p: 8,
                r: 1,
                salt: Vec::from_hex(
                    "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
                )
                    .unwrap(),
            }
        );
        assert_eq!(
            keystore.crypto.mac,
            Vec::from_hex("2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097")
                .unwrap()
        );
    }


    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_deserialize_pbkdf2_keystore_v4() {
        // Test vec from: https://eips.ethereum.org/EIPS/eip-2335
        let data = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                }
            },
            "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/0/0",
            "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
            "version": 4
        }"#;
        let keystore: EthKeystoreV4 = serde_json::from_str(data).unwrap();

        // Check outer level
        assert_eq!(keystore.version, 4);
        assert_eq!(
            keystore.uuid,
            Uuid::parse_str("64625def-3331-4eea-ab6f-782f3ed16a83")
                .unwrap()
                .to_string()
        );
        assert_eq!(
            keystore.description,
            "This is a test keystore that uses PBKDF2 to secure the secret.".to_string()
        );
        assert_eq!(
            keystore.pubkey,
            "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07".to_string()
        );
        assert_eq!(keystore.path, "m/12381/60/0/0".to_string());

        // Check Cipher
        assert_eq!(keystore.crypto.cipher.function, "aes-128-ctr");
        assert_eq!(
            keystore.crypto.cipher.params.iv,
            Vec::from_hex("264daa3f303d7259501c93d997d84fe6").unwrap()
        );
        assert_eq!(
            keystore.crypto.cipher.message,
            Vec::from_hex("cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad")
                .unwrap()
        );

        // Check KDF
        assert_eq!(keystore.crypto.kdf.function, KdfType::Pbkdf2);
        assert_eq!(
            keystore.crypto.kdf.params,
            KdfparamsType::Pbkdf2 {
                c: 262144,
                dklen: 32,
                prf: String::from("hmac-sha256"),
                salt: Vec::from_hex(
                    "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                )
                    .unwrap(),
            }
        );
        assert_eq!(keystore.crypto.kdf.message, Vec::from_hex("").unwrap());

        // Test Checksum
        assert_eq!(
            keystore.crypto.checksum.message,
            Vec::from_hex("8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1")
                .unwrap()
        );

        assert_eq!(keystore.crypto.checksum.function, HashFunction::Sha256);
    }

    #[test]
    fn test_deserialize_kdf() {
        let data = r#"
        {
            "function": "scrypt",
            "params": {
                "dklen": 32,
                "n": 262144,
                "p": 1,
                "r": 8,
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
            },
            "message": ""
        }"#;
        let _kdf: Kdf = serde_json::from_str(data).unwrap();
    }

    #[test]
    fn test_deserialize_checksum() {
        let data = r#"
        {
            "function": "sha256",
            "params": {},
            "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
        }"#;
        let _kdf: Checksum = serde_json::from_str(data).unwrap();
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_deserialize_scrypt_keystore_v4() {
        // Test vec from: https://eips.ethereum.org/EIPS/eip-2335
        let data = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
                        "r": 8,
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
                }
            },
            "description": "This is a test keystore that uses scrypt to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/3141592653/589793238",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "version": 4
        }"#;
        let keystore: EthKeystoreV4 = serde_json::from_str(data).unwrap();

        // Check outer level
        assert_eq!(keystore.version, 4);
        assert_eq!(
            keystore.uuid,
            Uuid::parse_str("1d85ae20-35c5-4611-98e8-aa14a633906f")
                .unwrap()
                .to_string()
        );
        assert_eq!(
            keystore.description,
            "This is a test keystore that uses scrypt to secure the secret.".to_string()
        );
        assert_eq!(
            keystore.pubkey,
            "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07".to_string()
        );
        assert_eq!(keystore.path, "m/12381/60/3141592653/589793238".to_string());

        // Check Cipher
        assert_eq!(keystore.crypto.cipher.function, "aes-128-ctr");
        assert_eq!(
            keystore.crypto.cipher.params.iv,
            Vec::from_hex("264daa3f303d7259501c93d997d84fe6").unwrap()
        );
        assert_eq!(
            keystore.crypto.cipher.message,
            Vec::from_hex("06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f")
                .unwrap()
        );
        // Check KDF
        assert_eq!(keystore.crypto.kdf.function, KdfType::Scrypt);
        assert_eq!(
            keystore.crypto.kdf.params,
            KdfparamsType::Scrypt {
                dklen: 32,
                n: 262144,
                p: 1,
                r: 8,
                salt: Vec::from_hex(
                    "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                )
                    .unwrap(),
            }
        );
        assert_eq!(keystore.crypto.kdf.message, Vec::from_hex("").unwrap());

        // Test Checksum
        assert_eq!(
            keystore.crypto.checksum.message,
            Vec::from_hex("d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484")
                .unwrap()
        );

        assert_eq!(keystore.crypto.checksum.function, HashFunction::Sha256);
    }
}
