use crypto::{
    aes,
    digest::Digest,
    hmac::Hmac,
    pbkdf2::pbkdf2,
    scrypt::{scrypt, ScryptParams},
    sha2::Sha256,
    sha3::Sha3,
};
use rand::{CryptoRng, Rng};
use std::{fs::File, io::Read, path::Path};

mod error;
mod keystore;

pub use error::Error;
pub use keystore::{EthKeystore, KdfparamsType};

const KEY_LENGTH: usize = 32usize;

#[allow(unused_variables)]
pub fn new<P, R, S>(path: P, rng: &mut R, password: S) -> Result<Vec<u8>, Error>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    S: AsRef<[u8]>,
{
    unimplemented!();
}

#[allow(unused_variables)]
pub fn decrypt_key<P, S>(path: P, password: S) -> Result<Vec<u8>, Error>
where
    P: AsRef<Path>,
    S: AsRef<[u8]>,
{
    // Read the file contents as string and deserialize it.
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let keystore: EthKeystore = serde_json::from_str(&contents)?;

    // Derive the key.
    let key = match keystore.crypto.kdfparams {
        KdfparamsType::Pbkdf2 {
            c,
            dklen,
            prf,
            salt,
        } => {
            let mut key = vec![0u8; dklen as usize];
            let mut hmac = Hmac::new(Sha256::new(), password.as_ref());
            pbkdf2(&mut hmac, &salt, c, key.as_mut_slice());
            key
        }
        KdfparamsType::Scrypt {
            dklen,
            n,
            p,
            r,
            salt,
        } => {
            let mut key = vec![0u8; dklen as usize];
            let log_n = (n as f32).log2() as u8;
            let scrypt_params = ScryptParams::new(log_n, r, p);
            scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice());
            key
        }
    };

    // Derive the MAC from the derived key and ciphertext.
    let mut hasher = Sha3::keccak256();
    let mut derived_mac = vec![0u8; KEY_LENGTH];
    hasher.input(&key[16..32]);
    hasher.input(&keystore.crypto.ciphertext);
    hasher.result(&mut derived_mac);
    if derived_mac != keystore.crypto.mac {
        return Err(Error::MacMismatch);
    }

    // Decrypt the private key bytes using AES-128-CTR
    let mut pk = vec![0u8; KEY_LENGTH];
    let mut decryptor = aes::ctr(
        aes::KeySize::KeySize128,
        &key,
        &keystore.crypto.cipherparams.iv,
    );
    decryptor.process(&keystore.crypto.ciphertext, &mut pk);

    Ok(pk)
}

#[allow(unused_variables)]
pub fn encrypt_key<P, S>(path: P, key: S, password: S) -> Result<(), Error>
where
    P: AsRef<Path>,
    S: AsRef<[u8]>,
{
    unimplemented!();
}
