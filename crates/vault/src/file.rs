//! On-disk format:
//!
//! ```json
//! { "format": "fernwerk-vault", "version": 1,
//!   "kdf": { "algorithm": "argon2id", "memoryKib": 65536, "iterations": 3, "parallelism": 1, "salt": "<b64>" },
//!   "nonce": "<b64>", "ciphertext": "<b64>" }
//! ```
//!
//! The header (`format`, `version`, `kdf`) is authenticated as AEAD associated data,
//! so tampering with it fails decryption like a wrong PIN would.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, Result};

const FORMAT: &str = "fernwerk-vault";
const VERSION: u32 = 1;

/// Upper bounds on KDF cost read from the file, so a tampered header can't make
/// unlocking allocate gigabytes before decryption fails.
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_ITERATIONS: u32 = 20;
const MAX_PARALLELISM: u32 = 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    #[serde(with = "b64")]
    salt: Vec<u8>,
}

impl Default for KdfParams {
    /// Argon2id, 64 MiB, 3 passes: roughly 0.3-0.6s on a desktop CPU.
    fn default() -> Self {
        Self {
            algorithm: "argon2id".into(),
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
            salt: Vec::new(),
        }
    }
}

impl KdfParams {
    /// Cheap parameters so tests run fast. Never use outside tests.
    pub fn insecure_for_tests() -> Self {
        Self {
            memory_kib: 8,
            iterations: 1,
            ..Self::default()
        }
    }

    pub(crate) fn with_fresh_salt(&self) -> Self {
        Self {
            salt: random_bytes::<16>().to_vec(),
            ..self.clone()
        }
    }
}

#[derive(Serialize)]
struct Header<'a> {
    format: &'a str,
    version: u32,
    kdf: &'a KdfParams,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    format: String,
    version: u32,
    kdf: KdfParams,
    #[serde(with = "b64")]
    nonce: Vec<u8>,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
}

pub(crate) fn derive_key(pin: &str, device_secret: &[u8], kdf: &KdfParams) -> Zeroizing<[u8; 32]> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .expect("valid argon2 params");
    let argon = Argon2::new_with_secret(device_secret, Algorithm::Argon2id, Version::V0x13, params)
        .expect("device secret within argon2 limits");
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pin.as_bytes(), &kdf.salt, key.as_mut())
        .expect("argon2 output length is valid");
    key
}

fn aad(kdf: &KdfParams) -> Vec<u8> {
    serde_json::to_vec(&Header {
        format: FORMAT,
        version: VERSION,
        kdf,
    })
    .expect("header serializes")
}

pub(crate) fn write(path: &Path, key: &[u8; 32], kdf: &KdfParams, plaintext: &[u8]) -> Result<()> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let nonce_bytes = random_bytes::<24>();
    let nonce = XNonce::try_from(&nonce_bytes[..]).expect("24-byte nonce");
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad(kdf),
            },
        )
        .map_err(|_| Error::Corrupt)?;

    let file = VaultFile {
        format: FORMAT.into(),
        version: VERSION,
        kdf: kdf.clone(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    };
    let json = serde_json::to_vec_pretty(&file).map_err(|_| Error::Corrupt)?;

    // Write-then-rename so a crash never leaves a half-written vault.
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    write_private(&tmp, &json)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Writes `bytes` to `path` readable by the owner only, and flushes them to disk so
/// the rename that follows can't publish an empty file after a crash.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// A successfully decrypted vault file.
pub(crate) struct Opened {
    pub kdf: KdfParams,
    pub key: Zeroizing<[u8; 32]>,
    pub plaintext: Zeroizing<Vec<u8>>,
}

pub(crate) fn read(path: &Path, pin: &str, device_secret: &[u8]) -> Result<Opened> {
    let raw = std::fs::read(path)?;
    let file: VaultFile = serde_json::from_slice(&raw).map_err(|_| Error::Corrupt)?;
    if file.format != FORMAT || file.version != VERSION || file.kdf.algorithm != "argon2id" {
        return Err(Error::Corrupt);
    }
    let nonce = XNonce::try_from(&file.nonce[..]).map_err(|_| Error::Corrupt)?;
    if file.kdf.memory_kib > MAX_MEMORY_KIB
        || file.kdf.iterations > MAX_ITERATIONS
        || file.kdf.parallelism > MAX_PARALLELISM
    {
        return Err(Error::Corrupt);
    }
    if Params::new(
        file.kdf.memory_kib,
        file.kdf.iterations,
        file.kdf.parallelism,
        Some(32),
    )
    .is_err()
    {
        return Err(Error::Corrupt);
    }

    let key = derive_key(pin, device_secret, &file.kdf);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key");
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &file.ciphertext,
                aad: &aad(&file.kdf),
            },
        )
        .map_err(|_| Error::WrongPin)?;
    Ok(Opened {
        kdf: file.kdf,
        key,
        plaintext: Zeroizing::new(plaintext),
    })
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS random number generator");
    buf
}

pub(crate) fn random_id() -> String {
    random_bytes::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

mod b64 {
    use super::{B64, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s).map_err(serde::de::Error::custom)
    }
}
