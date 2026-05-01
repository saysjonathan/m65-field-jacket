use crate::{Error, Result};
use std::path::{Path, PathBuf};

const M65_DIR: &str = ".m65";

// Roots

pub fn user_home() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| Error::Msg("HOME env var not set".into()))?;
    Ok(PathBuf::from(home))
}

pub fn repo_root() -> Result<PathBuf> {
    let home = user_home()?;
    let cwd = std::env::current_dir()?;
    let mut p: &Path = &cwd;

    loop {
        if p == home {
            return Err(Error::Msg(format!(
                "no .m65 directory found from {} up to $HOME ({})",
                cwd.display(),
                home.display()
            )));
        }

        if p.join(M65_DIR).is_dir() {
            return Ok(p.to_path_buf());
        }

        if p.join(".git").exists() {
            return Err(Error::Msg(format!(
                "no .m65 directory found in this repo (searched up to {})",
                p.display()
            )));
        }

        match p.parent() {
            Some(parent) => p = parent,
            None => {
                return Err(Error::Msg(
                    "no pocket directory found from cwd up to filesystem root".into(),
                ));
            }
        }
    }
}

pub fn init_repo_root() -> Result<PathBuf> {
    Ok(std::env::current_dir()?)
}

// Global builders

fn m65_home() -> Result<PathBuf> {
    Ok(user_home()?.join(M65_DIR))
}

pub fn config() -> Result<PathBuf> {
    Ok(m65_home()?.join("config"))
}

pub fn session() -> Result<PathBuf> {
    Ok(m65_home()?.join("session"))
}

pub fn identities_dir() -> Result<PathBuf> {
    Ok(m65_home()?.join("identities"))
}

pub fn identity_private(name: &str) -> Result<PathBuf> {
    Ok(identities_dir()?.join(name))
}

pub fn identity_public(name: &str) -> Result<PathBuf> {
    Ok(identities_dir()?.join(format!("{}.pub", name)))
}

// Pocket builders

pub fn pockets_dir(repo: &Path) -> PathBuf {
    repo.join(M65_DIR)
}

pub fn pocket_dir(repo: &Path, name: &str) -> PathBuf {
    pockets_dir(repo).join(name)
}

pub fn keyring(pocket_dir: &Path) -> PathBuf {
    pocket_dir.join("keyring")
}

pub fn secret(pocket_dir: &Path, name: &str) -> PathBuf {
    pocket_dir.join(format!("{name}.enc"))
}
