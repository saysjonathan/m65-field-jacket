use crate::cli::{SetArgs, SetCommands};
use crate::config::Config;
use crate::pocket::{Pocket, Unlocked};
use crate::stanza::read_stanzas;
use age_core::format::Stanza;
use anyhow::Context;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::prelude::*;
use std::path::{Path, PathBuf};

const NONCE_LENGTH: usize = 12;

#[derive(Debug, PartialEq, Eq)]
pub enum SecretKind {
    Env,
    File { target: String },
}

impl SecretKind {
    fn header_lines(&self) -> String {
        match self {
            SecretKind::Env => "-> mfj-type: env\n".to_owned(),
            SecretKind::File { target } => format!("-> mfj-type: file\n-> mfj-target: {target}\n"),
        }
    }
}

impl std::fmt::Display for SecretKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SecretKind::Env => "env",
            SecretKind::File { .. } => "file",
        })
    }
}

#[derive(Debug)]
pub struct SecretMeta {
    pub name: String,
    pub kind: SecretKind,
    pub created: u64,
}

impl SecretMeta {
    pub fn from_stanzas(stanzas: &[Stanza]) -> anyhow::Result<Self> {
        let mut name = None;
        let mut type_str = None;
        let mut target = None;
        let mut created = None;

        for s in stanzas {
            let val = s.args.first().cloned();
            match s.tag.as_str() {
                "mfj-name" => name = val,
                "mfj-type" => type_str = val,
                "mfj-target" => target = val,
                "mfj-created" => created = val.map(|v| v.parse()).transpose()?,
                _ => {}
            }
        }

        let name = name.ok_or_else(|| anyhow::anyhow!("missing mfj-name stanza"))?;
        let type_str = type_str.ok_or_else(|| anyhow::anyhow!("missing mfj-type stanza"))?;
        let created = created.ok_or_else(|| anyhow::anyhow!("missing mfj-created stanza"))?;
        let kind = match type_str.as_str() {
            "env" => {
                if target.is_some() {
                    anyhow::bail!("env secret has unexpected mfj-target");
                }
                SecretKind::Env
            }
            "file" => {
                let target = target
                    .ok_or_else(|| anyhow::anyhow!("missing mfj-target stanza for file secret"))?;
                SecretKind::File { target }
            }
            other => anyhow::bail!("unknown secret kind: {other}"),
        };

        Ok(Self {
            name,
            kind,
            created,
        })
    }
}

fn encrypt_and_write(
    pocket: &Pocket<Unlocked>,
    path: &Path,
    header: &str,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let ct = ChaCha20Poly1305::new(Key::from_slice(pocket.dek().expose()))
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    let mut ciphertext = Vec::with_capacity(NONCE_LENGTH + ct.len());
    ciphertext.extend_from_slice(&nonce_bytes);
    ciphertext.extend_from_slice(&ct);

    let mut out = Vec::from(header.as_bytes());
    out.extend_from_slice(&ciphertext);
    std::fs::write(path, &out)?;
    Ok(ciphertext)
}

#[derive(Debug)]
pub struct Secret {
    path: PathBuf,
    meta: SecretMeta,
    ciphertext: Vec<u8>,
}

impl Secret {
    pub fn read(path: &Path) -> anyhow::Result<Self> {
        let bytes =
            std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let sep = bytes
            .windows(4)
            .position(|w| w == b"---\n")
            .ok_or_else(|| anyhow::anyhow!("malformed .enc file separator"))?;
        let stanzas = read_stanzas(&bytes[..sep])?;
        let meta = SecretMeta::from_stanzas(&stanzas)?;
        let ciphertext = bytes[sep + 4..].to_vec();
        Ok(Self {
            path: path.to_owned(),
            meta,
            ciphertext,
        })
    }

    pub fn meta(&self) -> &SecretMeta {
        &self.meta
    }

    pub fn decrypt(&self, pocket: &Pocket<Unlocked>) -> anyhow::Result<Vec<u8>> {
        let (nonce, ciphertext) = self.ciphertext.split_at(NONCE_LENGTH);
        ChaCha20Poly1305::new(Key::from_slice(pocket.dek().expose()))
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("decryption failed: wrong key or corrupted data"))
    }

    pub fn delete(self) -> anyhow::Result<()> {
        std::fs::remove_file(&self.path)
            .with_context(|| format!("failed to remove secret: {}", self.path.display()))
    }
    fn create(
        pocket: &Pocket<Unlocked>,
        name: &str,
        kind: SecretKind,
        plaintext: &[u8],
    ) -> anyhow::Result<Self> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let header = format!(
            "age-encryption.org/v1\n\
            {}\
            -> mfj-name: {name}\n\
            -> mfj-created: {ts}\n\
            ---\n",
            kind.header_lines(),
        );

        let path = pocket.secret_path(name);
        let ciphertext = encrypt_and_write(pocket, &path, &header, plaintext)?;

        Ok(Self {
            path,
            meta: SecretMeta {
                name: name.to_owned(),
                kind,
                created: ts,
            },
            ciphertext,
        })
    }

    pub fn create_env(pocket: &Pocket<Unlocked>, name: &str, value: &[u8]) -> anyhow::Result<Self> {
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || name.starts_with(|c: char| c.is_ascii_digit())
        {
            anyhow::bail!("secret name must match [a-zA-Z_][a-zA-Z0-9_]*");
        }

        Self::create(pocket, name, SecretKind::Env, value)
    }

    pub fn create_file(
        pocket: &Pocket<Unlocked>,
        source: &Path,
        target: Option<&str>,
    ) -> anyhow::Result<Self> {
        let name = source
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("invalid source path: {}", source.display()))?;

        let target_str: String = target
            .map(String::from)
            .unwrap_or_else(|| source.to_string_lossy().into_owned());

        let contents = std::fs::read(&source)
            .with_context(|| format!("source file does not exist: {}", source.display()))?;

        Self::create(
            pocket,
            name,
            SecretKind::File { target: target_str },
            &contents,
        )
    }
}

pub fn list(pocket: String) -> anyhow::Result<()> {
    let pocket = Pocket::open(&pocket)?;
    for secret in pocket.secrets()? {
        let secret = secret?;
        let meta = secret.meta();
        match &meta.kind {
            SecretKind::File { target } => {
                println!("{}\t{}\t{}\t{}", meta.name, meta.kind, target, meta.created)
            }
            SecretKind::Env => println!("{}\t{}\t{}", meta.name, meta.kind, meta.created),
        }
    }

    Ok(())
}

pub fn get(pocket: String, name: String, config: &Config) -> anyhow::Result<()> {
    let pocket = Pocket::open(&pocket)?.unlock(config)?;
    let secret = pocket.secret(&name)?;
    let plaintext = secret.decrypt(&pocket)?;
    println!("{}", String::from_utf8(plaintext)?);
    Ok(())
}

pub fn remove(pocket: String, name: String) -> anyhow::Result<()> {
    let pocket = Pocket::open(&pocket)?;
    pocket.secret(&name)?.delete()
}

pub fn set(args: SetArgs, config: &Config) -> anyhow::Result<()> {
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

fn env(pocket: String, name: String, value: String, config: &Config) -> anyhow::Result<()> {
    let pocket = Pocket::open(&pocket)?.unlock(config)?;
    Secret::create_env(&pocket, &name, value.as_bytes())?;
    Ok(())
}

fn file(
    pocket: String,
    source: String,
    target: Option<String>,
    config: &Config,
) -> anyhow::Result<()> {
    let pocket = Pocket::open(&pocket)?.unlock(config)?;
    Secret::create_file(&pocket, Path::new(&source), target.as_deref())?;
    Ok(())
}
