use crate::cli::{IdentityArgs, IdentityCommands};
use crate::config::Config;
use crate::domain::identity::{Identity, IdentityName};
use crate::io::{Confirm, PassphraseSource};

pub fn dispatch(
    args: IdentityArgs,
    config: Option<Config>,
    passphrase: &dyn PassphraseSource,
    confirm: &dyn Confirm,
) -> anyhow::Result<()> {
    match args.command {
        IdentityCommands::Init { name, set_default } => init(name, set_default, config, passphrase),
        IdentityCommands::Default {} => default(config),
        IdentityCommands::SetDefault { name } => set_default(name, config),
        IdentityCommands::Show { name } => show(name),
        IdentityCommands::List {} => list(config),
        IdentityCommands::Remove { name } => remove(name, config, confirm),
    }
}

fn init(
    name: IdentityName,
    set_default: bool,
    config: Option<Config>,
    passphrase: &dyn PassphraseSource,
) -> anyhow::Result<()> {
    let (_identity, pubkey) = Identity::create(&name, passphrase)?;

    match config {
        Some(mut c) => {
            if set_default {
                c.default_identity = name.into();
                c.save()?
            }
        }
        None => {
            let c = Config::new(name.into());
            c.save()?
        }
    }

    println!("{}", pubkey);
    Ok(())
}

fn default(config: Option<Config>) -> anyhow::Result<()> {
    let c = Config::require(config)?;
    println!("{}", c.default_identity);
    Ok(())
}

fn set_default(name: IdentityName, config: Option<Config>) -> anyhow::Result<()> {
    let mut c = Config::require(config)?;
    Identity::open(&name)?;
    c.default_identity = name.into();
    c.save()?;
    Ok(())
}

fn show(name: IdentityName) -> anyhow::Result<()> {
    println!("{}", Identity::open(&name)?.recipient()?);
    Ok(())
}

fn list(config: Option<Config>) -> anyhow::Result<()> {
    let c = Config::require(config)?;
    for identity in Identity::list()? {
        let marker = if c.default_identity == identity.name().as_str() {
            "* "
        } else {
            "  "
        };
        println!("{}{}", marker, identity.name());
    }

    Ok(())
}

fn remove(name: IdentityName, config: Option<Config>, confirm: &dyn Confirm) -> anyhow::Result<()> {
    let c = Config::require(config)?;
    if c.default_identity == name.as_str() {
        anyhow::bail!(
            "cannot remove default identity '{}'; set a different default first",
            name
        );
    }

    if !confirm.confirm("Type the identity name to confirm removal: ", name.as_str())? {
        anyhow::bail!("name did not match; aborting");
    }

    Identity::open(&name)?.delete()?;
    println!("removed identity: {}", name);
    Ok(())
}
