use crate::cli::{IdentityArgs, IdentityCommands};

pub fn dispatch(args: IdentityArgs) -> anyhow::Result<()> {
    match args.command {
        IdentityCommands::Init { name } => init(name),
        IdentityCommands::Show { name } => show(name),
        IdentityCommands::List {} => list(),
        IdentityCommands::Remove { name } => remove(name),
    }
}

fn init(name: String) -> anyhow::Result<()> { Ok(()) }
fn show(name: String) -> anyhow::Result<()> { Ok(()) }
fn list() -> anyhow::Result<()> { Ok(()) }
fn remove(name: String) -> anyhow::Result<()> { Ok(()) }
