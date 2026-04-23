use crate::cli::{IdentityArgs, IdentityCommands};
use crate::config::{Config, m65_home};
use anyhow::Context;
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::prelude::*;
use secrecy::ExposeSecret;
use std::path::PathBuf;

fn identities_dir() -> anyhow::Result<PathBuf> {
    Ok(m65_home()?.join("identities"))
}

pub struct Locked;
pub struct Unlocked {
    inner: age::x25519::Identity,
}

pub struct Identity<S> {
    name: String,
    state: S,
}

impl<S> Identity<S> {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn recipient(&self) -> anyhow::Result<age::x25519::Recipient> {
        let path = identities_dir()?.join(format!("{}.pub", self.name));
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("identity pubkey not found: {}", self.name))?;

        contents
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid public key: {e}"))
    }
}

impl Identity<Locked> {
    pub fn open(name: &str) -> anyhow::Result<Self> {
        let path = identities_dir()?.join(name);
        if !path.exists() {
            anyhow::bail!("identity does not exist: {}", name);
        }
        Ok(Self {
            name: name.to_owned(),
            state: Locked,
        })
    }

    pub fn unlock(self) -> anyhow::Result<Identity<Unlocked>> {
        let path = identities_dir()?.join(&self.name);
        let blob =
            std::fs::read(&path).with_context(|| format!("identity not found: {}", self.name))?;
        let salt = &blob[0..16];
        let nonce = &blob[16..28];
        let ciphertext = &blob[28..];

        let passphrase =
            rpassword::prompt_password("Passphrase: ").context("failed to read passphrase")?;

        let mut hashkey = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &salt, &mut hashkey)
            .map_err(|e| anyhow::anyhow!("argon2 error: {e}"))?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&hashkey));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("decryption failed (wrong passphrase?)"))?;

        let key_str = std::str::from_utf8(&plaintext).context("decrypted key not valid UTF-8")?;
        let inner = key_str
            .parse::<age::x25519::Identity>()
            .map_err(|e| anyhow::anyhow!("invalid age private key: {e}"))?;

        Ok(Identity {
            name: self.name,
            state: Unlocked { inner },
        })
    }

    pub fn create(name: &str) -> anyhow::Result<(Self, age::x25519::Recipient)> {
        let identities_dir = identities_dir()?;
        std::fs::create_dir_all(&identities_dir).context("failed to create ~/.m65/identities")?;

        let identity_path = identities_dir.join(&name);
        let pub_path = identities_dir.join(format!("{name}.pub"));

        if identity_path.exists() {
            anyhow::bail!("identity already exists: {name}");
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
            .map_err(|e| anyhow::anyhow!("argon2 error: {e}"))?;

        let key_str = key.to_string();
        let plaintext = key_str.expose_secret().as_bytes();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&hashkey));
        let nonce_bytes: [u8; 12] = rand::rng().random();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

        let mut blob = Vec::new();
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        std::fs::write(&identity_path, &blob)?;
        std::fs::write(&pub_path, &pubkey.to_string())?;

        Ok((
            Self {
                name: name.to_owned(),
                state: Locked,
            },
            pubkey,
        ))
    }

    pub fn list() -> anyhow::Result<Vec<Self>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(identities_dir()?)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("pub") {
                continue;
            }
            if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                out.push(Self {
                    name: name.to_owned(),
                    state: Locked,
                })
            }
        }
        Ok(out)
    }

    pub fn delete(self) -> anyhow::Result<()> {
        let dir = identities_dir()?;
        std::fs::remove_file(dir.join(&self.name))?;
        std::fs::remove_file(dir.join(format!("{}.pub", self.name)))?;
        Ok(())
    }
}

impl Identity<Unlocked> {
    pub fn as_age(&self) -> &dyn age::Identity {
        &self.state.inner
    }
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
    let (_identity, pubkey) = Identity::create(&name)?;

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
    let c = Config::require(config)?;
    println!("{}", c.default_identity);
    Ok(())
}

fn set_default(name: String, config: Option<Config>) -> anyhow::Result<()> {
    let mut c = Config::require(config)?;
    Identity::open(&name)?;
    c.default_identity = name;
    c.save()?;
    Ok(())
}

fn show(name: String) -> anyhow::Result<()> {
    println!("{}", Identity::open(&name)?.recipient()?);
    Ok(())
}

fn list(config: Option<Config>) -> anyhow::Result<()> {
    let c = Config::require(config)?;
    for identity in Identity::list()? {
        let marker = if c.default_identity == identity.name() {
            "* "
        } else {
            "  "
        };
        println!("{}{}", marker, identity.name());
    }

    Ok(())
}

fn remove(name: String, config: Option<Config>) -> anyhow::Result<()> {
    let c = Config::require(config)?;
    if c.default_identity == name {
        anyhow::bail!(
            "cannot remove default identity '{}'; set a different default first",
            name
        );
    }

    print!("Type the identity name to confirm removal: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    if input.trim() != name {
        anyhow::bail!("name did not match; aborting");
    }

    Identity::open(&name)?.delete()?;
    println!("removed identity: {}", name);
    Ok(())
}
