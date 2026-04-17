use anyhow::Context;

pub fn identities_dir() -> anyhow::Result<std::path::PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(std::path::Path::new(&home).join(".m65").join("identities"))
}

