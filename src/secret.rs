use crate::cli::{SetArgs, SetCommands};
use crate::config::Config;
use crate::identity::decrypt_identity;
use crate::paths::pocket_dir;
use crate::stanza::read_stanzas;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::prelude::*;

pub fn list(pocket: String) -> anyhow::Result<()> {
    let pocket_dir = pocket_dir(&pocket)?;
    if !pocket_dir.try_exists()? {
        anyhow::bail!("keyring for pocket '{}' does not exist", pocket);
    }

    for entry in std::fs::read_dir(&pocket_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("enc") {
            continue;
        }

        let secret = std::fs::File::open(&path)?;
        let stanzas = read_stanzas(std::io::BufReader::new(secret))?;

        let map: std::collections::HashMap<&str, &str> = stanzas
            .iter()
            .filter_map(|s| Some((s.tag.as_str(), s.args.first()?.as_str())))
            .collect();
        let name = map.get("mfj-name").copied().unwrap_or("?");
        let kind = map.get("mfj-type").copied().unwrap_or("?");
        let target = map.get("mfj-target").copied();

        match target {
            Some(t) => println!("{name}\t{kind}\t{t}"),
            None => println!("{name}\t{kind}"),
        }
    }

    Ok(())
}

pub fn get(pocket: String, name: String, config: Option<Config>) -> anyhow::Result<()> {
    let c = Config::require(config)?;

    let pocket_dir = pocket_dir(&pocket)?;
    if !pocket_dir.exists() {
        anyhow::bail!(
            "pocket '{}' not initialized. run `mfj pocket init` to create a pocket",
            pocket
        );
    }

    let keyring = pocket_dir.join("keyring");
    if !keyring.exists() {
        anyhow::bail!("keyring for pocket '{}' does not exist", pocket);
    }

    let identity = decrypt_identity(&c.default_identity)?;
    let keyring_bytes = std::fs::read(&keyring)?;
    let decryptor = age::Decryptor::new(&keyring_bytes[..])?;
    let mut dek = Vec::new();
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;
    std::io::Read::read_to_end(&mut reader, &mut dek)?;
    anyhow::ensure!(dek.len() == 32, "DEK is not 32 bytes");

    let enc_file = pocket_dir.join(format!("{}.enc", name));
    if !enc_file.try_exists()? {
        anyhow::bail!("secret does not exist: {}", name);
    }

    let secret = std::fs::read(&enc_file)?;
    let sep = b"---\n";
    let sep_pos = secret
        .windows(4)
        .position(|w| w == sep)
        .ok_or_else(|| anyhow::anyhow!("malformed .enc file: missing separator"))?;
    let blob = &secret[sep_pos + 4..];

    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dek));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed: wrong key or corrupted data"))?;
    println!("{}", String::from_utf8(plaintext)?);

    Ok(())
}

pub fn remove(pocket: String, name: String) -> anyhow::Result<()> {
    let pocket_dir = pocket_dir(&pocket)?;
    if !pocket_dir.exists() {
        anyhow::bail!(
            "pocket '{}' not initialized. run `mfj pocket init` to create a pocket",
            pocket
        );
    }

    let secret = pocket_dir.join(format!("{}.enc", &name));
    if !secret.try_exists()? {
        anyhow::bail!("secret does not exist: {}", name);
    }

    std::fs::remove_file(secret)?;

    Ok(())
}

pub fn set(args: SetArgs, config: Option<Config>) -> anyhow::Result<()> {
    match args.command {
        SetCommands::Env {
            pocket,
            name,
            value,
        } => env(pocket, name, value, config),
        SetCommands::File {
            pocket,
            source,
            target,
        } => file(pocket, source, target, config),
    }
}

fn env(pocket: String, name: String, value: String, config: Option<Config>) -> anyhow::Result<()> {
    let c = Config::require(config)?;

    let pocket_dir = pocket_dir(&pocket)?;
    if !pocket_dir.exists() {
        anyhow::bail!(
            "pocket '{}' not initialized. run `mfj pocket init` to create a pocket",
            pocket
        );
    }

    let keyring = pocket_dir.join("keyring");
    if !keyring.exists() {
        anyhow::bail!("keyring for pocket '{}' does not exist", pocket);
    }

    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        || name.starts_with(|c: char| c.is_ascii_digit())
    {
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

fn file(
    pocket: String,
    source: String,
    target: Option<String>,
    config: Option<Config>,
) -> anyhow::Result<()> {
    Ok(())
}
