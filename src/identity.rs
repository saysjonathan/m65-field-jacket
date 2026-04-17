use anyhow::Context;
use argon2::Argon2;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use crate::cli::{IdentityArgs, IdentityCommands};
use crate::paths::identities_dir;
use rand::prelude::*;
use secrecy::ExposeSecret;

pub fn dispatch(args: IdentityArgs) -> anyhow::Result<()> {
    match args.command {
        IdentityCommands::Init { name } => init(name),
        IdentityCommands::Show { name } => show(name),
        IdentityCommands::List {} => list(),
        IdentityCommands::Remove { name } => remove(name),
    }
}

fn init(name: String) -> anyhow::Result<()> {
    let identities_dir = identities_dir()?;

    let identity = identities_dir.join(&name);
    let identity_pub = identities_dir.join(format!("{}.pub", &name));

    std::fs::create_dir_all(&identities_dir)
        .context("failed to create ~/.m65/identities")?;

    if std::fs::exists(&identity).context("failed to check identity path")? {
        anyhow::bail!("identity already exists: {}", &name);
    }

    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();


    let passphrase = rpassword::prompt_password("Passphrase: ")
        .context("failed to read passphrase")?;
    let confirm = rpassword::prompt_password("Confirm passphrase: ")
        .context("failed to read password confirmation")?;

    if passphrase != confirm {
        anyhow::bail!("passphrases do not match");
    }

    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);

    let mut hashkey = [0u8; 32];
    Argon2::default().hash_password_into(passphrase.as_bytes(), &salt, &mut hashkey)
        .map_err(|e| anyhow::anyhow!("argon2 error: {}", e))?;

    let key_str = key.to_string();
    let plaintext = key_str.expose_secret().as_bytes();


   let cipher = ChaCha20Poly1305::new(Key::from_slice(&hashkey));
   let nonce_bytes: [u8; 12] = rand::rng().random();
   let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
      .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

    let mut blob = Vec::new();
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    std::fs::write(&identity, &blob)?;
    std::fs::write(&identity_pub, &pubkey.to_string())?;

    println!("{}", pubkey);

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

fn list() -> anyhow::Result<()> { Ok(()) }
fn remove(name: String) -> anyhow::Result<()> { Ok(()) }
