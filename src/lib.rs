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
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use uuid::Uuid;

mod error;
mod keystore;

use keystore::{CipherparamsJson, CryptoJson, KdfType, KdfparamsType};

pub use error::Error;
pub use keystore::EthKeystore;

const DEFAULT_CIPHER: &str = "aes-128-ctr";
const DEFAULT_KEY_SIZE: usize = 32usize;
const DEFAULT_IV_SIZE: usize = 16usize;
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 13u8;
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

pub fn new<P, R, S>(dir: P, rng: &mut R, password: S) -> Result<(Vec<u8>, String), Error>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    S: AsRef<[u8]>,
{
    // Generate a random private key.
    let mut pk = vec![0u8; DEFAULT_KEY_SIZE];
    rng.fill_bytes(pk.as_mut_slice());

    let uuid = encrypt_key(dir, rng, pk.clone(), password)?;
    Ok((pk, uuid))
}

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
            prf: _,
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
    let mut derived_mac = vec![0u8; DEFAULT_KEY_SIZE];
    hasher.input(&key[16..32]);
    hasher.input(&keystore.crypto.ciphertext);
    hasher.result(&mut derived_mac);
    if derived_mac != keystore.crypto.mac {
        return Err(Error::MacMismatch);
    }

    // Decrypt the private key bytes using AES-128-CTR
    let mut pk = vec![0u8; DEFAULT_KEY_SIZE];
    let mut decryptor = aes::ctr(
        aes::KeySize::KeySize128,
        &key,
        &keystore.crypto.cipherparams.iv,
    );
    decryptor.process(&keystore.crypto.ciphertext, &mut pk);

    Ok(pk)
}

pub fn encrypt_key<P, R, B, S>(dir: P, rng: &mut R, pk: B, password: S) -> Result<String, Error>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    B: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    // Generate a random salt.
    let mut salt = vec![0u8; DEFAULT_KEY_SIZE];
    rng.fill_bytes(salt.as_mut_slice());

    // Derive the key.
    let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
    let scrypt_params = ScryptParams::new(
        DEFAULT_KDF_PARAMS_LOG_N,
        DEFAULT_KDF_PARAMS_R,
        DEFAULT_KDF_PARAMS_P,
    );
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice());

    // Encrypt the private key using AES-128-CTR.
    let mut ciphertext = vec![0u8; DEFAULT_KEY_SIZE];
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];
    rng.fill_bytes(iv.as_mut_slice());
    let mut encryptor = aes::ctr(aes::KeySize::KeySize128, &key, &iv);
    encryptor.process(pk.as_ref(), &mut ciphertext);

    // Calculate the MAC.
    let mut hasher = Sha3::keccak256();
    let mut mac = vec![0u8; DEFAULT_KEY_SIZE];
    hasher.input(&key[16..32]);
    hasher.input(&ciphertext);
    hasher.result(&mut mac);

    // Construct and serialize the encrypted JSON keystore.
    let id = Uuid::new_v4();
    let keystore = EthKeystore {
        id,
        version: 3,
        crypto: CryptoJson {
            cipher: String::from(DEFAULT_CIPHER),
            cipherparams: CipherparamsJson { iv },
            ciphertext,
            kdf: KdfType::Scrypt,
            kdfparams: KdfparamsType::Scrypt {
                dklen: DEFAULT_KDF_PARAMS_DKLEN,
                n: 2u32.pow(DEFAULT_KDF_PARAMS_LOG_N as u32),
                p: DEFAULT_KDF_PARAMS_P,
                r: DEFAULT_KDF_PARAMS_R,
                salt,
            },
            mac,
        },
    };
    let contents = serde_json::to_string(&keystore)?;

    // Create a file in write-only mode, to store the encrypted JSON keystore.
    let mut file = File::create(dir.as_ref().join(id.to_string()))?;
    file.write_all(contents.as_bytes())?;

    Ok(id.to_string())
}
