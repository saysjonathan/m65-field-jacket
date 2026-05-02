use crate::cli::{IdentityArgs, IdentityCommands};
use crate::commands::Ctx;
use crate::config::Config;
use crate::domain::identity::{Identity, IdentityName};

pub fn dispatch(args: IdentityArgs, ctx: &Ctx) -> anyhow::Result<()> {
    match args.command {
        IdentityCommands::Init { name, set_default } => init(name, set_default, ctx),
        IdentityCommands::Default {} => default(ctx),
        IdentityCommands::SetDefault { name } => set_default(name, ctx),
        IdentityCommands::Show { name } => show(name),
        IdentityCommands::List {} => list(ctx),
        IdentityCommands::Remove { name } => remove(name, ctx),
    }
}

fn init(name: IdentityName, set_default: bool, ctx: &Ctx) -> anyhow::Result<()> {
    let (_identity, pubkey) = Identity::create(&name, &*ctx.passphrase)?;

    match ctx.config.clone() {
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

fn default(ctx: &Ctx) -> anyhow::Result<()> {
    let c = Config::require(&ctx.config)?;
    println!("{}", c.default_identity);
    Ok(())
}

fn set_default(name: IdentityName, ctx: &Ctx) -> anyhow::Result<()> {
    let mut c = Config::require(&ctx.config)?.clone();
    Identity::open(&name)?;
    c.default_identity = name.into();
    c.save()?;
    Ok(())
}

fn show(name: IdentityName) -> anyhow::Result<()> {
    println!("{}", Identity::open(&name)?.recipient()?);
    Ok(())
}

fn list(ctx: &Ctx) -> anyhow::Result<()> {
    let c = Config::require(&ctx.config)?;
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

fn remove(name: IdentityName, ctx: &Ctx) -> anyhow::Result<()> {
    let c = Config::require(&ctx.config)?;
    if c.default_identity == name.as_str() {
        anyhow::bail!(
            "cannot remove default identity '{}'; set a different default first",
            name
        );
    }

    if !ctx
        .confirm
        .confirm("Type the identity name to confirm removal: ", name.as_str())?
    {
        anyhow::bail!("name did not match; aborting");
    }

    Identity::open(&name)?.delete()?;
    println!("removed identity: {}", name);
    Ok(())
}
