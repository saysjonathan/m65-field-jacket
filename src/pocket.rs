use crate::cli::{PocketArgs, PocketCommands};
use crate::config::Config;
use crate::dek::Dek;
use crate::identity::decrypt_identity;
use crate::keyring::Keyring;
use crate::paths::identities_dir;
use crate::secret::Secret;
use anyhow::Context;
use std::path::{Path, PathBuf};

const POCKET_BASE: &str = ".m65";

pub struct Locked;
pub struct Unlocked {
    dek: Dek,
}

pub struct Pocket<S> {
    name: String,
    dir: PathBuf,
    state: S,
}

impl<S> Pocket<S> {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn keyring_path(&self) -> PathBuf {
        self.dir.join("keyring")
    }

    pub fn secret_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{}.enc", name))
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
        let path = self.secret_path(name);
        if !path.try_exists()? {
            anyhow::bail!("secret does not exist: {name}");
        }
        Secret::read(&path)
    }
}

impl Pocket<Locked> {
    pub fn create(name: &str, recipient: &age::x25519::Recipient) -> anyhow::Result<Self> {
        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            anyhow::bail!("pocket name must be alphanumeric");
        }

        if name.len() > 64 {
            anyhow::bail!("pocket name must be <=64 chars");
        }

        let dir = Path::new(POCKET_BASE).join(name);
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

    pub fn open(name: &str) -> anyhow::Result<Self> {
        let dir = Path::new(POCKET_BASE).join(name);
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
        let id = decrypt_identity(&config.default_identity)?;
        let keyring = Keyring::load(&self)?;
        let dek = keyring.decrypt_dek(&id)?;
        Ok(Pocket {
            name: self.name,
            dir: self.dir,
            state: Unlocked { dek },
        })
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

pub fn dispatch(args: PocketArgs, config: Option<Config>) -> anyhow::Result<()> {
    match args.command {
        PocketCommands::Init { name } => init(name, config),
        PocketCommands::List {} => list(),
        PocketCommands::Remove { name } => remove(name),
    }
}

fn init(name: String, config: Option<Config>) -> anyhow::Result<()> {
    let c = Config::require(config)?;
    let pubkey_path = identities_dir()?.join(format!("{}.pub", c.default_identity));
    let pubkey = std::fs::read_to_string(&pubkey_path)
        .with_context(|| format!("identity not found: {}", c.default_identity));
    let recipient: age::x25519::Recipient = pubkey?
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid public key: {e}"))?;

    Pocket::create(&name, &recipient)?;
    Ok(())
}

fn list() -> anyhow::Result<()> {
    for entry in std::fs::read_dir(".m65")? {
        println!("{}", entry?.file_name().to_string_lossy());
    }

    Ok(())
}

fn remove(name: String) -> anyhow::Result<()> {
    let pocket = Pocket::open(&name)?;

    print!("Type the pocket name to confirm removal: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    if input.trim() != name {
        anyhow::bail!("name did not match; aborting");
    }
    pocket.delete()?;
    println!("removed pocket: {}", name);
    Ok(())
}
