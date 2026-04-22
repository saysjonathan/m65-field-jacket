use crate::cli::{IdentityArgs, IdentityCommands};
use crate::config::Config;
use crate::paths::identities_dir;
use anyhow::Context;
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::prelude::*;
use secrecy::ExposeSecret;

pub fn decrypt_identity(name: &str) -> anyhow::Result<age::x25519::Identity> {
    let identity = identities_dir()?.join(name);
    let blob = std::fs::read(&identity)
        .with_context(|| format!("identity not found: {}", name))?;
    let salt = &blob[0..16];
    let nonce = &blob[16..28];
    let ciphertext = &blob[28..];

    let passphrase =
        rpassword::prompt_password("Passphrase: ").context("failed to read passphrase")?;

    let mut hashkey = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt, &mut hashkey)
        .map_err(|e| anyhow::anyhow!("argon2 error: {}", e))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&hashkey));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed (wrong passphrase?)"))?;

    let key_str = std::str::from_utf8(&plaintext).context("decrypted key not valid UTF-8")?;
    key_str.parse::<age::x25519::Identity>()
        .map_err(|e| anyhow::anyhow!("invalid age private key: {e}"))
}

pub fn dispatch(args: IdentityArgs, config: Option<Config>) -> anyhow::Result<()> {
    match args.command {
        IdentityCommands::Init { name, set_default } => init(name, set_default, config),
        IdentityCommands::Default {} => default(config),
        IdentityCommands::SetDefault { name } => set_default(name, config),
        IdentityCommands::Show { name } => show(name),
        IdentityCommands::List {} => list(config),
        IdentityCommands::Remove { name } => remove(name, config),
    }
}

fn init(name: String, set_default: bool, config: Option<Config>) -> anyhow::Result<()> {
    let identities_dir = identities_dir()?;

    let identity = identities_dir.join(&name);
    let identity_pub = identities_dir.join(format!("{}.pub", &name));

    std::fs::create_dir_all(&identities_dir).context("failed to create ~/.m65/identities")?;

    if std::fs::exists(&identity).context("failed to check identity path")? {
        anyhow::bail!("identity already exists: {}", &name);
    }

    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();

    let passphrase =
        rpassword::prompt_password("Passphrase: ").context("failed to read passphrase")?;
    let confirm = rpassword::prompt_password("Confirm passphrase: ")
        .context("failed to read password confirmation")?;

    if passphrase != confirm {
        anyhow::bail!("passphrases do not match");
    }

    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);

    let mut hashkey = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt, &mut hashkey)
        .map_err(|e| anyhow::anyhow!("argon2 error: {}", e))?;

    let key_str = key.to_string();
    let plaintext = key_str.expose_secret().as_bytes();

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&hashkey));
    let nonce_bytes: [u8; 12] = rand::rng().random();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

    let mut blob = Vec::new();
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    std::fs::write(&identity, &blob)?;
    std::fs::write(&identity_pub, &pubkey.to_string())?;

    match config {
        Some(mut c) => {
            if set_default {
                c.default_identity = name;
                c.save()?
            }
        }
        None => {
            let c = Config::new(name);
            c.save()?
        }
    }

    println!("{}", pubkey);

    Ok(())
}

fn default(config: Option<Config>) -> anyhow::Result<()> {
    let c = config.ok_or_else(|| {
        anyhow::anyhow!("No identity initialized. Run 'mfj identity init' to create one.")
    })?;
    println!("{}", c.default_identity);
    Ok(())
}

fn set_default(name: String, config: Option<Config>) -> anyhow::Result<()> {
    match config {
        Some(mut c) => {
            if !identities_dir()?.join(&name).exists() {
                anyhow::bail!("identity does not exist: {}", name);
            }

            c.default_identity = name;
            c.save()?
        }
        None => {
            anyhow::bail!("No config found. Run 'mfj identity init' first.")
        }
    }

    Ok(())
}

fn show(name: String) -> anyhow::Result<()> {
    let identities_dir = identities_dir()?;
    let identity_pub = identities_dir.join(format!("{}.pub", &name));
    let pubkey = std::fs::read_to_string(&identity_pub)
        .map_err(|_| anyhow::anyhow!("identity does not exist: {}", &name))?;
    println!("{}", pubkey.trim());
    Ok(())
}

fn list(config: Option<Config>) -> anyhow::Result<()> {
    let default = config.map(|c| c.default_identity);
    for entry in std::fs::read_dir(identities_dir()?)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pub") {
            continue;
        }
        if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
            let marker = if default.as_deref() == Some(name) {
                "* "
            } else {
                " "
            };
            println!("{}{}", marker, name);
        }
    }

    Ok(())
}

fn remove(name: String, config: Option<Config>) -> anyhow::Result<()> {
    if let Some(c) = config {
        if c.default_identity == name {
            anyhow::bail!(
                "cannot remove default identity '{}'; set a different default first",
                name
            );
        }
    }

    print!("Type the identity name to confirm removal: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    if input.trim() != name {
        anyhow::bail!("name did not match; aborting");
    }

    let dir = identities_dir()?;
    std::fs::remove_file(dir.join(&name))?;
    std::fs::remove_file(dir.join(format!("{name}.pub")))?;
    println!("removed identity: {}", name);

    Ok(())
}
