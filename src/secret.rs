use crate::cli::{SetArgs, SetCommands};
use crate::config::Config;
use crate::paths::pocket_dir;
use crate::identity::decrypt_identity;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::prelude::*;

pub fn set(args: SetArgs, config: Option<Config>) -> anyhow::Result<()> {
    match args.command {
        SetCommands::Env { pocket, name, value } => env(pocket, name, value, config),
        SetCommands::File { pocket, source, target } => file(pocket, source, target, config),
    }
}

fn env(pocket: String, name: String, value: String, config: Option<Config>) -> anyhow::Result<()> {
    let c = config.ok_or_else(|| {
        anyhow::anyhow!("no identity initialized. Run `mfj identity init` to create one.")
    })?;

    let pocket_dir = pocket_dir(&pocket)?;
    if ! pocket_dir.exists() {
        anyhow::bail!("pocket '{}' not initialized. run `mfj pocket init` to create a pocket", pocket);
    }

    let keyring = pocket_dir.join("keyring");
    if ! keyring.exists() {
        anyhow::bail!("keyring for pocket '{}' does not exist", pocket);
    }

    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || name.starts_with(|c: char| c.is_ascii_digit()) {
        anyhow::bail!("secret name must match [a-zA-Z_][a-zA-Z0-9_]*");
    }

    let identity = decrypt_identity(&c.default_identity)?;
    let keyring_bytes = std::fs::read(&keyring)?;
    let decryptor = age::Decryptor::new(&keyring_bytes[..])?;
    let mut dek = Vec::new();
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;
    std::io::Read::read_to_end(&mut reader, &mut dek)?;
    anyhow::ensure!(dek.len() == 32, "DEK is not 32 bytes");

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let header = format!(
        "age-encryption.org/v1\n\
        -> mfj-type: env\n\
        -> mfj-name: {name}\n\
        -> mfj-created: {ts}\n\
        ---\n"
    );

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dek));
    let nonce_bytes: [u8; 12] = rand::rng().random();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), value.as_bytes())
        .map_err(|e| anyhow::anyhow!("encryption of value failed: {}", e))?;

    let mut out = Vec::new();
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    std::fs::write(pocket_dir.join(format!("{}.enc", name)), &out)?;

    Ok(())
}

fn file(pocket: String, source: String, target: Option<String>, config: Option<Config>) -> anyhow::Result<()> {
    Ok(())
}
