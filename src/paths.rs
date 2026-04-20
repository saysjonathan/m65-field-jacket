use anyhow::Context;

pub fn m65_dir() -> anyhow::Result<std::path::PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(std::path::Path::new(&home).join(".m65"))
}

pub fn identities_dir() -> anyhow::Result<std::path::PathBuf> {
    Ok(m65_dir()?.join("identities"))
}

