mod keystore;

pub use keystore::EthKeystoreV4;

use crate::KeystoreError;

pub fn decrypt<S>(_keystore: EthKeystoreV4, _password: S) -> Result<Vec<u8>, KeystoreError>
where
    S: AsRef<[u8]>,
{
    todo!()
}
