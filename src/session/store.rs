use crate::domain::dek::Dek;
use crate::storage;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SessionRecord {
    entries: HashMap<String, CachedDek>,
}

impl SessionRecord {
    pub fn resume() -> anyhow::Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(&path).context("failed to read session")?;
        serde_json::from_str(&contents).context("failed to parse session")
    }

    pub fn seal(&self) -> anyhow::Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("failed to create ~/.m65")?;
        }
        let contents = serde_json::to_string_pretty(self).context("failed to serialize session")?;
        std::fs::write(&path, contents).context("failed to write session")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .context("failed to chmod session")?;
        }
        Ok(())
    }

    pub fn path() -> anyhow::Result<PathBuf> {
        Ok(storage::session()?)
    }

    pub fn get(&self, key: &str) -> Option<Dek> {
        let entry = self.entries.get(key)?;
        if entry.expires_unix <= now_unix() {
            return None;
        }
        Some(Dek::new(entry.bytes))
    }

    pub fn insert(&mut self, key: &str, dek: &Dek, ttl: u64) {
        self.entries.insert(
            key.to_owned(),
            CachedDek {
                bytes: *dek.expose(),
                expires_unix: now_unix() + ttl,
            },
        );
    }

    pub fn invalidate(&mut self, key: &str) -> bool {
        self.entries.remove(key).is_some()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn remove() -> anyhow::Result<()> {
        let path = Self::path()?;
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("failed to remove session: {}", &path.display()))?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct CachedDek {
    #[serde(with = "hex_bytes")]
    bytes: [u8; Dek::BYTES],
    expires_unix: u64,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(d: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected {} bytes, got {}", N, v.len()))
        })
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}
