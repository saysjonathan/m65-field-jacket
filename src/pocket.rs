use crate::cli::{PocketArgs, PocketCommands};
use crate::config::Config;
use crate::dek::Dek;
use crate::identity::{Identity, IdentityName};
use crate::keyring::Keyring;
use crate::secret::Secret;
use crate::session;
use crate::storage;
use anyhow::Context;
use std::path::{Path, PathBuf};

pub struct Locked;
pub struct Unlocked {
    dek: Dek,
}

pub struct Pocket<S> {
    name: PocketName,
    dir: PathBuf,
    state: S,
}

impl<S> Pocket<S> {
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn secrets(&self) -> anyhow::Result<impl Iterator<Item = anyhow::Result<Secret>>> {
        Ok(
            std::fs::read_dir(&self.dir)?.filter_map(|entry| match entry {
                Ok(e) if e.path().extension().and_then(|x| x.to_str()) == Some("enc") => {
                    Some(Secret::read(&e.path()))
                }
                Ok(_) => None,
                Err(e) => Some(Err(e.into())),
            }),
        )
    }

    pub fn secret(&self, name: &str) -> anyhow::Result<Secret> {
        let path = storage::secret(&self.dir, name);
        if !path.try_exists()? {
            anyhow::bail!("secret does not exist: {name}");
        }
        Secret::read(&path)
    }

    pub fn session_key(&self) -> anyhow::Result<String> {
        let abs = std::fs::canonicalize(&self.dir)
            .with_context(|| format!("failed to canonicalize: {}", self.dir.display()))?;
        Ok(abs.to_string_lossy().into_owned())
    }
}

impl Pocket<Locked> {
    pub fn create(
        name: &PocketName,
        recipient: &age::x25519::Recipient,
        repo_root: &Path,
    ) -> anyhow::Result<Self> {
        let dir = storage::pocket_dir(repo_root, name.as_str());
        if dir.exists() {
            anyhow::bail!("pocket already exists: {}", name);
        }

        let (keyring, _dek) = Keyring::create(recipient)?;

        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
        keyring.save(&dir)?;

        let tmp_dir = dir.join(".tmp");
        std::fs::create_dir(&tmp_dir)
            .with_context(|| format!("failed to create temp dir {}", tmp_dir.display()))?;

        Ok(Self {
            name: name.to_owned(),
            dir,
            state: Locked,
        })
    }

    pub fn open(name: &PocketName, repo_root: &Path) -> anyhow::Result<Self> {
        let dir = storage::pocket_dir(repo_root, name.as_str());
        if !dir.exists() {
            anyhow::bail!("pocket not initialized: {name}. run `mfj pocket init` to create");
        }
        Ok(Self {
            name: name.to_owned(),
            dir,
            state: Locked,
        })
    }

    pub fn unlock(self, config: &Config) -> anyhow::Result<Pocket<Unlocked>> {
        let key = self.session_key()?;
        if let Some(dek) = session::try_resume(&key)? {
            return Ok(self.into_unlocked(dek));
        }

        let name: IdentityName = config.default_identity.parse()?;
        let id = Identity::open(&name)?.unlock()?;
        let keyring = Keyring::load(self.dir())?;
        let dek = keyring.decrypt_dek(id.as_age())?;
        session::establish(&key, &dek, config)?;
        Ok(self.into_unlocked(dek))
    }

    fn into_unlocked(self, dek: Dek) -> Pocket<Unlocked> {
        Pocket {
            name: self.name,
            dir: self.dir,
            state: Unlocked { dek },
        }
    }

    pub fn delete(self) -> anyhow::Result<()> {
        std::fs::remove_dir_all(&self.dir).map_err(Into::into)
    }
}

impl Pocket<Unlocked> {
    pub fn dek(&self) -> &Dek {
        &self.state.dek
    }
}

#[derive(Clone, Debug)]
pub struct PocketName(String);

impl PocketName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for PocketName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        if s.is_empty() {
            anyhow::bail!("pocket name must not be empty");
        }

        if s.len() > 64 {
            anyhow::bail!("pocket name must be <=64 chars");
        }

        if !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            anyhow::bail!("pocket name must be alphanumeric");
        }

        Ok(Self(s.to_owned()))
    }
}

impl std::fmt::Display for PocketName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for PocketName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

pub fn dispatch(args: PocketArgs, config: Option<Config>) -> anyhow::Result<()> {
    match args.command {
        PocketCommands::Init { name } => init(name, config),
        PocketCommands::List {} => list(),
        PocketCommands::Remove { name } => remove(name),
    }
}

fn init(name: PocketName, config: Option<Config>) -> anyhow::Result<()> {
    let c = Config::require(config)?;
    let id: IdentityName = c.default_identity.parse()?;
    let recipient = Identity::open(&id)?.recipient()?;
    let repo_root = storage::init_repo_root()?;
    Pocket::create(&name, &recipient, &repo_root)?;
    Ok(())
}

fn list() -> anyhow::Result<()> {
    let repo_root = storage::repo_root()?;
    for entry in std::fs::read_dir(storage::pockets_dir(&repo_root))? {
        println!("{}", entry?.file_name().to_string_lossy());
    }

    Ok(())
}

fn remove(name: PocketName) -> anyhow::Result<()> {
    let repo_root = storage::repo_root()?;
    let pocket = Pocket::open(&name, &repo_root)?;

    print!("Type the pocket name to confirm removal: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    if input.trim() != name.as_str() {
        anyhow::bail!("name did not match; aborting");
    }
    pocket.delete()?;
    println!("removed pocket: {}", name);
    Ok(())
}

pub fn lock(pocket: Option<PocketName>) -> anyhow::Result<()> {
    match pocket {
        Some(name) => {
            let repo_root = storage::repo_root()?;
            let key = Pocket::open(&name, &repo_root)?.session_key()?;
            session::invalidate_pocket(&key)?;
            println!("locked: {}", name);
        }
        None => {
            session::invalidate_all()?;
            println!("locked all pockets");
        }
    }
    Ok(())
}

pub fn unlock(name: PocketName, config: &Config) -> anyhow::Result<()> {
    let repo_root = storage::repo_root()?;
    Pocket::open(&name, &repo_root)?.unlock(config)?;
    println!("unlocked: {}", name);
    Ok(())
}
