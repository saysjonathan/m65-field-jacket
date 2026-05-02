use crate::cli::{SetArgs, SetCommands};
use crate::commands::Ctx;
use crate::config::Config;
use crate::domain::name::{EnvSecretName, FileSecretName, PocketName};
use crate::domain::pocket::Pocket;
use crate::domain::secret::{Secret, SecretKind};
use crate::storage;
use std::path::Path;

pub fn list(pocket: PocketName) -> anyhow::Result<()> {
    let repo_root = storage::repo_root()?;
    let pocket = Pocket::open(&pocket, &repo_root)?;
    for secret in pocket.secrets()? {
        let secret = secret?;
        let meta = secret.meta();
        match &meta.kind {
            SecretKind::File { target } => {
                println!("{}\t{}\t{}\t{}", meta.name, meta.kind, target, meta.created)
            }
            SecretKind::Env => println!("{}\t{}\t{}", meta.name, meta.kind, meta.created),
        }
    }

    Ok(())
}

pub fn get(pocket: PocketName, name: String, ctx: &Ctx) -> anyhow::Result<()> {
    let repo_root = storage::repo_root()?;
    let pocket = Pocket::open(&pocket, &repo_root)?
        .unlock(Config::require(&ctx.config)?, &*ctx.passphrase)?;
    let secret = pocket.secret(&name)?;
    let plaintext = secret.decrypt(&pocket)?;
    println!("{}", String::from_utf8(plaintext)?);
    Ok(())
}

pub fn remove(pocket: PocketName, name: String) -> anyhow::Result<()> {
    let repo_root = storage::repo_root()?;
    let pocket = Pocket::open(&pocket, &repo_root)?;
    pocket.secret(&name)?.delete()
}

pub fn set(args: SetArgs, ctx: &Ctx) -> anyhow::Result<()> {
    match args.command {
        SetCommands::Env {
            pocket,
            name,
            value,
        } => env(pocket, name, value, ctx),
        SetCommands::File {
            pocket,
            source,
            target,
            name,
        } => file(pocket, source, target, name, ctx),
    }
}

fn env(pocket: PocketName, name: EnvSecretName, value: String, ctx: &Ctx) -> anyhow::Result<()> {
    let repo_root = storage::repo_root()?;
    let pocket = Pocket::open(&pocket, &repo_root)?
        .unlock(Config::require(&ctx.config)?, &*ctx.passphrase)?;
    Secret::create_env(&pocket, &name, value.as_bytes())?;
    Ok(())
}

fn file(
    pocket: PocketName,
    source: String,
    target: Option<String>,
    name: Option<FileSecretName>,
    ctx: &Ctx,
) -> anyhow::Result<()> {
    let repo_root = storage::repo_root()?;
    let pocket = Pocket::open(&pocket, &repo_root)?
        .unlock(Config::require(&ctx.config)?, &*ctx.passphrase)?;
    Secret::create_file(
        &pocket,
        Path::new(&source),
        target.as_deref(),
        name.as_ref(),
    )?;
    Ok(())
}
