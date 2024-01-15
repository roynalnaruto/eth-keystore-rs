#![cfg_attr(docsrs, feature(doc_cfg))]
//! A minimalist library to interact with encrypted JSON keystores.
//! Version 3 matches specs from [Web3 Secret Storage Definition](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).
//! Version 4 matches specs from [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

use aes::{
    cipher::{self, InnerIvInit, KeyInit, StreamCipherCore},
    Aes128,
};
use digest::{Digest, Update};
use hmac::Hmac;
use keystore::{Checksum, ChecksumParams, Cipher, HashFunction, Kdf};
use pbkdf2::pbkdf2;
use rand::{CryptoRng, Rng};
use scrypt::{scrypt, Params as ScryptParams};
use sha2::Sha256;
use sha3::Keccak256;
use uuid::Uuid;

use std::{fs::File, path::Path};

mod error;
mod keystore;
mod utils;

pub use error::KeystoreError;
pub use keystore::{CipherparamsJson, CryptoJsonV4, EthKeystoreV4, KdfType, KdfparamsType};
use crate::keystore::{CipherparamsJsonV3, CryptoJsonV3, EthKeystoreV3};

#[cfg(feature = "geth-compat")]
use utils::geth_compat::address_from_pk;

const DEFAULT_CIPHER: &str = "aes-128-ctr";
const DEFAULT_KEY_SIZE: usize = 32usize;
const DEFAULT_IV_SIZE: usize = 16usize;
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 18u8;
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

/// Decrypts an encrypted JSON keystore at the provided `path` using the provided `password`.
/// Decryption supports the [Scrypt](https://tools.ietf.org/html/rfc7914.html) and
/// [PBKDF2](https://ietf.org/rfc/rfc2898.txt) key derivation functions.
///
/// # Example
///
/// ```no_run
/// use eth_keystore::decrypt_key_v3;
/// use std::path::Path;
///
/// # async fn foobar() -> Result<(), Box<dyn std::error::Error>> {
/// let keypath = Path::new("./keys/my-key");
/// let private_key = decrypt_key_v3(&keypath, "password_to_keystore")?;
/// # Ok(())
/// # }
/// ```
pub fn decrypt_key_v3<P, S>(path: P, password: S) -> Result<Vec<u8>, KeystoreError>
    where
        P: AsRef<Path>,
        S: AsRef<[u8]>,
{
    // Read the file contents as string and deserialize it.
    let mut file = File::open(path)?;
    let keystore = serde_json::from_reader(&mut file)?;
    decrypt_keystore_v3(keystore, password)
}

pub fn decrypt_keystore_v3<S>(keystore: EthKeystoreV3, password: S) -> Result<Vec<u8>, KeystoreError>
    where
        S: AsRef<[u8]>,
{
    // Derive the key.
    let key = match keystore.crypto.kdfparams {
        KdfparamsType::Pbkdf2 {
            c,
            dklen,
            prf: _,
            salt,
        } => {
            let mut key = vec![0u8; dklen as usize];
            pbkdf2::<Hmac<Sha256>>(password.as_ref(), &salt, c, key.as_mut_slice());
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
            let log_n = n.ilog2() as u8;
            let scrypt_params = ScryptParams::new(log_n, r, p)?;
            scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;
            key
        }
    };

    // Derive the MAC from the derived key and ciphertext.
    let derived_mac = Keccak256::new()
        .chain(&key[16..32])
        .chain(&keystore.crypto.ciphertext)
        .finalize();

    if derived_mac.as_slice() != keystore.crypto.mac.as_slice() {
        return Err(KeystoreError::MacMismatch);
    }

    // Decrypt the private key bytes using AES-128-CTR
    let decryptor =
        Aes128Ctr::new(&key[..16], &keystore.crypto.cipherparams.iv[..16]).expect("invalid length");

    let mut pk = keystore.crypto.ciphertext;
    decryptor.apply_keystream(&mut pk);

    Ok(pk)
}

/// Encrypts the given private key using the [Scrypt](https://tools.ietf.org/html/rfc7914.html)
/// password-based key derivation function, and stores it in the provided directory. On success, it
/// returns the `id` (Uuid) generated for this keystore.
///
/// # Example
///
/// ```no_run
/// use eth_keystore::encrypt_key_v3;
/// use rand::RngCore;
/// use std::path::Path;
///
/// # async fn foobar() -> Result<(), Box<dyn std::error::Error>> {
/// let dir = Path::new("./keys");
/// let mut rng = rand::thread_rng();
///
/// // Construct a 32-byte random private key.
/// let mut private_key = vec![0u8; 32];
/// rng.fill_bytes(private_key.as_mut_slice());
///
/// // Since we specify a custom filename for the keystore, it will be stored in `$dir/my-key`
/// let name = encrypt_key_v3(&dir, &mut rng, &private_key, "password_to_keystore", Some("my-key"))?;
/// # Ok(())
/// # }
/// ```
pub fn encrypt_key_v3<P, R, B, S>(
    dir: P,
    rng: &mut R,
    pk: B,
    password: S,
    name: Option<&str>,
) -> Result<String, KeystoreError>
    where
        P: AsRef<Path>,
        R: Rng + CryptoRng,
        B: AsRef<[u8]>,
        S: AsRef<[u8]>,
{
    let keystore = encrypt_keystore_v3(rng, pk, password)?;

    // Set the keystore id to the provided name or to the generated uuid while encrypting the keystore
    let id = if let Some(name) = name {
        name.to_string()
    } else {
        keystore.id.to_string()
    };

    // Create file with keystore content
    let mut file = File::create(dir.as_ref().join(id.clone()))?;
    serde_json::to_writer(&mut file, &keystore)?;

    // Return the keystore id
    Ok(id)
}
pub fn encrypt_keystore_v3<R, B, S>(
    rng: &mut R,
    priv_key: B,
    password: S,
) -> Result<EthKeystoreV3, KeystoreError>
    where
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
    )?;
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

    // Encrypt the private key using AES-128-CTR.
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];
    rng.fill_bytes(iv.as_mut_slice());

    let encryptor = Aes128Ctr::new(&key[..16], &iv[..16]).expect("invalid length");

    let mut ciphertext = priv_key.as_ref().to_vec();
    encryptor.apply_keystream(&mut ciphertext);

    // Calculate the MAC.
    let mac = Keccak256::new()
        .chain(&key[16..32])
        .chain(&ciphertext)
        .finalize();

    let id = Uuid::new_v4();

    // Construct and serialize the encrypted JSON keystore.
    let keystore = EthKeystoreV3 {
        id,
        version: 3,
        crypto: CryptoJsonV3 {
            cipher: String::from(DEFAULT_CIPHER),
            cipherparams: CipherparamsJsonV3 { iv },
            ciphertext: ciphertext.to_vec(),
            kdf: KdfType::Scrypt,
            kdfparams: KdfparamsType::Scrypt {
                dklen: DEFAULT_KDF_PARAMS_DKLEN,
                n: 2u32.pow(DEFAULT_KDF_PARAMS_LOG_N as u32),
                p: DEFAULT_KDF_PARAMS_P,
                r: DEFAULT_KDF_PARAMS_R,
                salt,
            },
            mac: mac.to_vec(),
        },
        #[cfg(feature = "geth-compat")]
        address: address_from_pk(&priv_key)?,
    };

    Ok(keystore)
}


/// Decrypts an encrypted JSON keystore at the provided `path` using the provided `password`.
/// Decryption supports the [Scrypt](https://tools.ietf.org/html/rfc7914.html) and
/// [PBKDF2](https://ietf.org/rfc/rfc2898.txt) key derivation functions.
///
/// # Example
///
/// ```no_run
/// use eth_keystore::decrypt_key_v4;
/// use std::path::Path;
///
/// # async fn foobar() -> Result<(), Box<dyn std::error::Error>> {
/// let key_path = Path::new("./keys/my-key");
/// let private_key = decrypt_key_v4(&key_path, "password_to_keystore")?;
/// # Ok(())
/// # }
/// ```
pub fn decrypt_key_v4<P, S>(path: P, password: S) -> Result<Vec<u8>, KeystoreError>
    where
        P: AsRef<Path>,
        S: AsRef<[u8]>,
{
    // Read the file contents as string and deserialize it into a `EthKeystore` struct.
    let mut file = File::open(path)?;
    let keystore = serde_json::from_reader(&mut file)?;
    decrypt_keystore_v4(keystore, password)
}

pub fn decrypt_keystore_v4<S>(keystore: EthKeystoreV4, password: S) -> Result<Vec<u8>, KeystoreError>
    where
        S: AsRef<[u8]>,
{
    // Derive the key.
    let key = match keystore.crypto.kdf.params {
        KdfparamsType::Pbkdf2 {
            c,
            dklen,
            prf: _,
            salt,
        } => {
            let mut key = vec![0u8; dklen as usize];
            pbkdf2::<Hmac<Sha256>>(password.as_ref(), &salt, c, key.as_mut_slice());
            key
        }
        KdfparamsType::Scrypt {
            dklen,
            n,
            r,
            p,
            salt,
        } => {
            let mut key = vec![0u8; dklen as usize];
            let log_n = n.ilog2() as u8;
            let scrypt_params = ScryptParams::new(log_n, r, p)?;
            scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;
            key
        }
    };

    // Derive the MAC from the derived key and ciphertext.
    let derived_mac = Sha256::new()
        .chain(&key[16..32])
        .chain(&keystore.crypto.cipher.message)
        .finalize();

    if derived_mac.as_slice() != keystore.crypto.checksum.message.as_slice() {
        return Err(KeystoreError::MacMismatch);
    }

    // Decrypt the private key bytes using AES-128-CTR
    let decryptor = Aes128Ctr::new(&key[..16], &keystore.crypto.cipher.params.iv[..16])
        .expect("invalid length");

    let mut pk = keystore.crypto.cipher.message;
    decryptor.apply_keystream(&mut pk);

    Ok(pk)
}

/// Encrypts the given private key using the [Scrypt](https://tools.ietf.org/html/rfc7914.html)
/// password-based key derivation function, and stores it in the provided directory. On success, it
/// returns the `id` (Uuid) generated for this keystore or the provided `name` if it was provided.
///
/// # Example
///
/// ```no_run
/// use eth_keystore::encrypt_key_v4;
/// use rand::RngCore;
/// use std::path::Path;
///
/// # async fn foobar() -> Result<(), Box<dyn std::error::Error>> {
/// let dir = Path::new("./keys");
/// let mut rng = rand::thread_rng();
///
/// // Construct a 32-byte random private key.
/// let mut private_key = vec![0u8; 32];
/// rng.fill_bytes(private_key.as_mut_slice());
///
/// // Since we specify a custom filename for the keystore, it will be stored in `$dir/my-key`
/// let name = encrypt_key_v4(&dir, &mut rng, &private_key, "password_to_keystore", Some("my-key"))?;
/// # Ok(())
/// # }
/// ```
pub fn encrypt_key_v4<P, R, B, S>(
    dir: P,
    rng: &mut R,
    pk: B,
    password: S,
    name: Option<&str>,
) -> Result<String, KeystoreError>
    where
        P: AsRef<Path>,
        R: Rng + CryptoRng,
        B: AsRef<[u8]>,
        S: AsRef<[u8]>,
{
    let keystore = encrypt_keystore_v4(rng, pk, None::<&str>, password)?;

    // Set the keystore id to the provided name or to the generated uuid while encrypting the keystore
    let id = if let Some(name) = name {
        name.to_string()
    } else {
        keystore.uuid.clone()
    };

    // Create file with keystore content
    let mut file = File::create(dir.as_ref().join(id.clone()))?;
    serde_json::to_writer(&mut file, &keystore)?;

    // Return the keystore id
    Ok(id)
}

pub fn encrypt_keystore_v4<R, B, S, P>(
    rng: &mut R,
    priv_key: B,
    pub_key: Option<P>,
    password: S,
) -> Result<EthKeystoreV4, KeystoreError>
    where
        R: Rng + CryptoRng,
        B: AsRef<[u8]>,
        S: AsRef<[u8]>,
        P: AsRef<str>,
{
    let pubkey = match pub_key {
        Some(pk) => pk.as_ref().to_string(),
        None => {
            let bls_sk = match blst::min_pk::SecretKey::from_bytes(priv_key.as_ref()) {
                Ok(sk) => sk,
                Err(e) => return Err(KeystoreError::BLSError(e)),
            };
            let bls_pk = bls_sk.sk_to_pk().compress();
            hex::encode(bls_pk)
        }
    };

    // Generate a random salt.
    let mut salt = vec![0u8; DEFAULT_KEY_SIZE];
    rng.fill_bytes(salt.as_mut_slice());

    // Derive the key.
    let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
    let scrypt_params = ScryptParams::new(
        DEFAULT_KDF_PARAMS_LOG_N,
        DEFAULT_KDF_PARAMS_R,
        DEFAULT_KDF_PARAMS_P,
    )?;
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

    // Encrypt the private key using AES-128-CTR.
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];
    rng.fill_bytes(iv.as_mut_slice());

    let encryptor = Aes128Ctr::new(&key[..16], &iv[..16]).expect("invalid length");

    let mut ciphertext = priv_key.as_ref().to_vec();
    encryptor.apply_keystream(&mut ciphertext);

    // Calculate the MAC.
    let mac = Sha256::new()
        .chain(&key[16..32])
        .chain(&ciphertext)
        .finalize();

    // As per as the EIP-2334
    let uuid = Uuid::new_v4().to_string();
    let version = 4;
    let path = String::from("m/12381/3600/0/0/0");
    let description = String::from("Version 4 BLS keystore");

    // Construct and serialize the encrypted JSON keystore.
    let keystore = EthKeystoreV4 {
        crypto: CryptoJsonV4 {
            kdf: Kdf {
                function: KdfType::Scrypt,
                params: KdfparamsType::Scrypt {
                    dklen: DEFAULT_KDF_PARAMS_DKLEN,
                    n: 2u32.pow(DEFAULT_KDF_PARAMS_LOG_N as u32),
                    p: DEFAULT_KDF_PARAMS_P,
                    r: DEFAULT_KDF_PARAMS_R,
                    salt,
                },
                message: vec![],
            },
            checksum: Checksum {
                function: HashFunction::Sha256,
                params: ChecksumParams {},
                message: mac.to_vec(),
            },
            cipher: Cipher {
                function: String::from(DEFAULT_CIPHER),
                params: CipherparamsJson { iv },
                message: ciphertext.to_vec(),
            },
        },
        description,
        pubkey,
        path,
        uuid,
        version,
    };

    Ok(keystore)
}

struct Aes128Ctr {
    inner: ctr::CtrCore<Aes128, ctr::flavors::Ctr128BE>,
}

impl Aes128Ctr {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self, cipher::InvalidLength> {
        let cipher = aes::Aes128::new_from_slice(key).unwrap();
        let inner = ctr::CtrCore::inner_iv_slice_init(cipher, iv).unwrap();
        Ok(Self { inner })
    }

    fn apply_keystream(self, buf: &mut [u8]) {
        self.inner.apply_keystream_partial(buf.into());
    }
}