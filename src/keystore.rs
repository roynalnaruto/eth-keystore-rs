use serde::{Deserialize, Deserializer, Serialize};

use crate::{v3, v4};

#[derive(Debug, Serialize)]
#[serde(tag = "version")]
pub enum EthKeystore {
    #[serde(rename = "3")]
    V3(v3::EthKeystoreV3),

    // TODO: add a v4 feature flag
    #[serde(rename = "4")]
    V4(v4::EthKeystoreV4),
}

impl<'de> Deserialize<'de> for EthKeystore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = serde_json::Value::deserialize(deserializer)?;

        match v["version"].as_i64() {
            // TODO tests/test-key/my_keystore has no version field
            // should we default to v3 to preserve compatibility, or raise an error?
            Some(3) | None => {
                let v3 = serde_json::from_value::<v3::EthKeystoreV3>(v)
                    .map_err(|_| serde::de::Error::custom("asd"))?;
                Ok(EthKeystore::V3(v3))
            }
            Some(4) => {
                let v4 = serde_json::from_value::<v4::EthKeystoreV4>(v)
                    .map_err(|_| serde::de::Error::custom("asd"))?;
                Ok(EthKeystore::V4(v4))
            }
            v => Err(serde::de::Error::custom(format!(
                "Unsupported version: {}",
                v.unwrap_or_default()
            ))),
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
/// Types of key derivition functions supported by the Web3 Secret Storage.
pub enum KdfType {
    Pbkdf2,
    Scrypt,
}

#[cfg(test)]
mod tests {

    use hex::FromHex;
    use uuid::Uuid;

    use crate::keystore::EthKeystore;
    use crate::v3::{KdfType, KdfparamsType};

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_deserialize_pbkdf2() {
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
        let keystore: EthKeystore = serde_json::from_str(data).unwrap();

        match keystore {
            EthKeystore::V3(_) => (),
            _ => panic!("not v3"), // TODO: how to properly fail here?
        };
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_deserialize_scrypt() {
        // Test vec from: https://eips.ethereum.org/EIPS/eip-2335

        use hex::FromHex;
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

        let keystore: EthKeystore = serde_json::from_str(data).unwrap();

        match keystore {
            EthKeystore::V4(_) => (),
            _ => panic!("not v3"), // TODO: how to properly fail here?
        };
    }
}
