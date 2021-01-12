use std::fmt;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
/// An error thrown when interacting with the eth-keystore crate.
pub enum KeystoreError {
    /// An error thrown while decrypting an encrypted JSON keystore if the calculated MAC does not
    /// match the MAC declared in the keystore.
    MacMismatch,
    /// An error thrown by the Rust `std::io` module.
    StdIo(String),
    /// An error thrown by the [Serde JSON](https://docs.serde.rs/serde_json/) crate.
    SerdeJson(String),
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                KeystoreError::MacMismatch => String::from("MAC Mismatch"),
                KeystoreError::StdIo(e) => format!("IO: {}", e),
                KeystoreError::SerdeJson(e) => format!("serde-json: {}", e),
            }
        )
    }
}

impl From<std::io::Error> for KeystoreError {
    fn from(e: std::io::Error) -> KeystoreError {
        KeystoreError::StdIo(e.to_string())
    }
}

impl From<serde_json::Error> for KeystoreError {
    fn from(e: serde_json::Error) -> KeystoreError {
        KeystoreError::SerdeJson(e.to_string())
    }
}
