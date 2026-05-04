use crate::config::Config;
use crate::domain::dek::Dek;
use crate::domain::identity::Identity;
use crate::domain::keyring::Keyring;
use crate::domain::name::PocketName;
use crate::domain::secret::Secret;
use crate::io::PassphraseSource;
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

    pub fn unlock(
        self,
        config: &Config,
        passphrase: &dyn PassphraseSource,
    ) -> anyhow::Result<Pocket<Unlocked>> {
        let key = self.session_key()?;
        if let Some(dek) = session::try_resume(&key)? {
            return Ok(self.into_unlocked(dek));
        }

        let id = Identity::open(&config.default_identity)?.unlock(passphrase)?;
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
