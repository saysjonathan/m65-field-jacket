use crate::paths::m65_dir;
use anyhow::Context;
use serde::{Deserialize, Serialize};

const DEFAULT_SESSION_TTL: u64 = 28800;

fn default_ttl() -> u64 {
    DEFAULT_SESSION_TTL
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub default_identity: String,
    #[serde(default = "default_ttl")]
    pub session_ttl_seconds: u64,
}

impl Config {
    pub fn new(default_identity: String) -> Self {
        Self {
            default_identity,
            session_ttl_seconds: DEFAULT_SESSION_TTL,
        }
    }

    pub fn load() -> anyhow::Result<Option<Self>> {
        let path = m65_dir()?.join("config");
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(&path).context("failed to read config")?;
        let config = serde_json::from_str::<Self>(&contents).context("failed to parse config")?;
        Ok(Some(config))
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = m65_dir()?.join("config");
        let contents = serde_json::to_string_pretty(self).context("failed to serialize config")?;
        std::fs::write(&path, contents).context("failed to write config")
    }
}
