use anyhow::Context;
use std::path::{Path, PathBuf};

pub fn m65_dir() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(Path::new(&home).join(".m65"))
}

pub fn identities_dir() -> anyhow::Result<PathBuf> {
    Ok(m65_dir()?.join("identities"))
}

pub fn pocket_dir(name: &str) -> anyhow::Result<PathBuf> {
    Ok(Path::new(".m65").join(name))
}
