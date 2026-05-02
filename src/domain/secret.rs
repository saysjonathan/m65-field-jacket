use crate::crypto;
use crate::domain::name::{EnvSecretName, FileSecretName};
use crate::domain::pocket::{Pocket, Unlocked};
use crate::domain::stanza::read_stanzas;
use crate::storage;
use age_core::format::Stanza;
use anyhow::Context;
use std::path::{Path, PathBuf};

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
    let nonce_bytes = crypto::random_nonce();
    let ct = crypto::encrypt(pocket.dek().expose(), &nonce_bytes, plaintext)?;

    let mut ciphertext = Vec::with_capacity(crypto::NONCE_LEN + ct.len());
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
        let (nonce, ciphertext) = self
            .ciphertext
            .split_first_chunk::<{ crypto::NONCE_LEN }>()
            .ok_or_else(|| anyhow::anyhow!("malformed secret ciphertext"))?;
        Ok(crypto::decrypt(pocket.dek().expose(), nonce, ciphertext)?)
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
        let path = storage::secret(pocket.dir(), name);
        if path.exists() {
            let existing = Secret::read(&path)?;
            if std::mem::discriminant(&existing.meta.kind) != std::mem::discriminant(&kind) {
                anyhow::bail!(
                    "secret {name} already exists as {} kind",
                    existing.meta.kind
                );
            }
        }

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

    pub fn create_env(
        pocket: &Pocket<Unlocked>,
        name: &EnvSecretName,
        value: &[u8],
    ) -> anyhow::Result<Self> {
        Self::create(pocket, name.as_str(), SecretKind::Env, value)
    }

    pub fn create_file(
        pocket: &Pocket<Unlocked>,
        source: &Path,
        target: Option<&str>,
        name: Option<&FileSecretName>,
    ) -> anyhow::Result<Self> {
        let resolved: FileSecretName = match name {
            Some(n) => n.clone(),
            None => {
                let raw = source
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| anyhow::anyhow!("invalid source path: {}", source.display()))?;
                raw.parse().with_context(|| {
                    format!("derived name '{raw}' invalid; provide --name to override")
                })?
            }
        };

        let target_str: String = target
            .map(String::from)
            .unwrap_or_else(|| source.to_string_lossy().into_owned());

        let contents = std::fs::read(&source)
            .with_context(|| format!("source file does not exist: {}", source.display()))?;

        Self::create(
            pocket,
            resolved.as_str(),
            SecretKind::File { target: target_str },
            &contents,
        )
    }
}
