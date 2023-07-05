use hex::{FromHex, ToHex};
use serde::{Deserialize, Deserializer, Serializer};

#[cfg(feature = "geth-compat")]
pub mod geth_compat {
    use ethereum_types::H160 as Address;
    use k256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
    use sha3::{Digest, Keccak256};

    use crate::KeystoreError;

    /// Converts a K256 SigningKey to an Ethereum Address
    pub fn address_from_pk<S>(pk: S) -> Result<Address, KeystoreError>
    where
        S: AsRef<[u8]>,
    {
        let secret_key = SigningKey::from_bytes(pk.as_ref())?;
        let public_key = PublicKey::from(&secret_key.verifying_key());
        let public_key = public_key.to_encoded_point(/* compress = */ false);
        let public_key = public_key.as_bytes();
        debug_assert_eq!(public_key[0], 0x04);
        let hash = keccak256(&public_key[1..]);
        Ok(Address::from_slice(&hash[12..]))
    }

    /// Compute the Keccak-256 hash of input bytes.
    fn keccak256<S>(bytes: S) -> [u8; 32]
    where
        S: AsRef<[u8]>,
    {
        let mut hasher = Keccak256::new();
        hasher.update(bytes.as_ref());
        hasher.finalize().into()
    }
}

pub(crate) fn buffer_to_hex<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&buffer.encode_hex::<String>())
}

pub(crate) fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string())))
}
