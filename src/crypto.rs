use anyhow::{Result, anyhow};
use argon2::Argon2;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use rand::prelude::*;
use secrecy::SecretBox;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;

pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| anyhow!("encryption failed: wrong key or corrupted data"))
}

pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("decryption failed: wrong key or corrupted data"))
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    salt
}

pub fn derive_kek(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<SecretBox<[u8; KEY_LEN]>> {
    let mut bytes = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut bytes)
        .map_err(|e| anyhow!(format!("argon2 error: {e}")))?;
    Ok(SecretBox::new(Box::new(bytes)))
}
