use crate::config::m65_home;
use crate::dek::Dek;
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
        Ok(m65_home()?.join("session"))
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
