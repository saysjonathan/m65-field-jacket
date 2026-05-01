mod cli;
mod config;
mod crypto;
mod dek;
mod error;
mod identity;
mod keyring;
mod pocket;
mod secret;
mod session;
mod stanza;

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

    match cli.command {
        Identity(args) => identity::dispatch(args, config)?,
        Pocket(args) => pocket::dispatch(args, config)?,
        Get { pocket, name } => secret::get(pocket, name, &config::Config::require(config)?)?,
        Remove { pocket, name } => secret::remove(pocket, name)?,
        Set(args) => secret::set(args, &config::Config::require(config)?)?,
        List { pocket } => secret::list(pocket)?,
        Lock { pocket } => pocket::lock(pocket)?,
        Unlock { pocket } => pocket::unlock(pocket, &config::Config::require(config)?)?,
    }

    Ok(())
}
