use hex::{FromHex, ToHex};
use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
pub struct EthKeystore {
    pub crypto: CryptoJson,
    pub id: Uuid,
    pub version: u8,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CryptoJson {
    pub cipher: String,
    pub cipherparams: CipherparamsJson,
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub ciphertext: Vec<u8>,
    pub kdf: KdfType,
    pub kdfparams: KdfparamsType,
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub mac: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CipherparamsJson {
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub iv: Vec<u8>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfType {
    Pbkdf2,
    Scrypt,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
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
        p: u32,
        r: u32,
        #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
        salt: Vec<u8>,
    },
}

pub fn buffer_to_hex<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&buffer.encode_hex::<String>())
}

pub fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
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

    #[test]
    fn test_deserialize_scrypt() {
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
        let keystore: EthKeystore = serde_json::from_str(data).unwrap();
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
}
