use crate::cli::{PocketArgs, PocketCommands};
use crate::config::Config;
use crate::domain::identity::{Identity, IdentityName};
use crate::domain::pocket::{Pocket, PocketName};
use crate::io::{Confirm, PassphraseSource};
use crate::session;
use crate::storage;

pub fn dispatch(
    args: PocketArgs,
    config: Option<Config>,
    confirm: &dyn Confirm,
) -> anyhow::Result<()> {
    match args.command {
        PocketCommands::Init { name } => init(name, config),
        PocketCommands::List {} => list(),
        PocketCommands::Remove { name } => remove(name, confirm),
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

fn remove(name: PocketName, confirm: &dyn Confirm) -> anyhow::Result<()> {
    let repo_root = storage::repo_root()?;
    let pocket = Pocket::open(&name, &repo_root)?;

    if !confirm.confirm("Type the pocket name to confirm removal: ", name.as_str())? {
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

pub fn unlock(
    name: PocketName,
    config: &Config,
    passphrase: &dyn PassphraseSource,
) -> anyhow::Result<()> {
    let repo_root = storage::repo_root()?;
    Pocket::open(&name, &repo_root)?.unlock(config, passphrase)?;
    println!("unlocked: {}", name);
    Ok(())
}
