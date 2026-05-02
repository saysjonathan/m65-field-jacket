mod cli;
mod commands;
mod config;
mod crypto;
mod domain;
mod error;
mod io;
mod session;
mod storage;

use crate::cli::Commands::{Get, Identity, List, Lock, Pocket, Remove, Set, Unlock};
use clap::Parser;
pub use error::{Error, Result};

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    let config = config::Config::load()?;
    let passphrase = io::TtyPrompt;
    let confirm = io::TtyConfirm;

    match cli.command {
        Identity(args) => commands::identity::dispatch(args, config, &passphrase, &confirm)?,
        Pocket(args) => commands::pocket::dispatch(args, config, &confirm)?,
        Get { pocket, name } => {
            commands::secret::get(pocket, name, &config::Config::require(config)?, &passphrase)?
        }
        Remove { pocket, name } => commands::secret::remove(pocket, name)?,
        Set(args) => commands::secret::set(args, &config::Config::require(config)?, &passphrase)?,
        List { pocket } => commands::secret::list(pocket)?,
        Lock { pocket } => commands::pocket::lock(pocket)?,
        Unlock { pocket } => {
            commands::pocket::unlock(pocket, &config::Config::require(config)?, &passphrase)?
        }
    }

    Ok(())
}
