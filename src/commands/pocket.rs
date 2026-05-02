use crate::cli::{PocketArgs, PocketCommands};
use crate::commands::Ctx;
use crate::config::Config;
use crate::domain::identity::Identity;
use crate::domain::name::{IdentityName, PocketName};
use crate::domain::pocket::Pocket;
use crate::session;
use crate::storage;

pub fn dispatch(args: PocketArgs, ctx: &Ctx) -> anyhow::Result<()> {
    match args.command {
        PocketCommands::Init { name } => init(name, ctx),
        PocketCommands::List {} => list(),
        PocketCommands::Remove { name } => remove(name, ctx),
    }
}

fn init(name: PocketName, ctx: &Ctx) -> anyhow::Result<()> {
    let c = Config::require(&ctx.config)?;
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

fn remove(name: PocketName, ctx: &Ctx) -> anyhow::Result<()> {
    let repo_root = storage::repo_root()?;
    let pocket = Pocket::open(&name, &repo_root)?;

    if !ctx
        .confirm
        .confirm("Type the pocket name to confirm removal: ", name.as_str())?
    {
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

pub fn unlock(name: PocketName, ctx: &Ctx) -> anyhow::Result<()> {
    let repo_root = storage::repo_root()?;
    Pocket::open(&name, &repo_root)?.unlock(Config::require(&ctx.config)?, &*ctx.passphrase)?;
    println!("unlocked: {}", name);
    Ok(())
}
