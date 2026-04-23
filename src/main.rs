mod cli;
mod config;
mod dek;
mod identity;
mod keyring;
mod pocket;
mod secret;
mod stanza;

use crate::cli::Commands::{Get, Identity, List, Pocket, Remove, Set};
use clap::Parser;

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
    }

    Ok(())
}
