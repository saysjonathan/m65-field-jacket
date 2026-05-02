mod cli;
mod commands;
mod config;
mod crypto;
mod domain;
mod io;
mod session;
mod storage;

use crate::cli::Commands::{Get, Identity, List, Lock, Pocket, Remove, Set, Unlock};
use anyhow::Result;
use clap::Parser;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = cli::Cli::parse();
    let ctx = commands::Ctx {
        config: config::Config::load()?,
        passphrase: Box::new(io::TtyPrompt),
        confirm: Box::new(io::TtyConfirm),
    };

    match cli.command {
        // Identity commands
        Identity(args) => commands::identity::dispatch(args, &ctx)?,

        // Pocket commands
        Pocket(args) => commands::pocket::dispatch(args, &ctx)?,

        // Secret commands
        Get { pocket, name } => commands::secret::get(pocket, name, &ctx)?,
        Remove { pocket, name } => commands::secret::remove(pocket, name)?,
        Set(args) => commands::secret::set(args, &ctx)?,
        List { pocket } => commands::secret::list(pocket)?,

        // Session commands
        Lock { pocket } => commands::pocket::lock(pocket)?,
        Unlock { pocket } => commands::pocket::unlock(pocket, &ctx)?,
    }

    Ok(())
}
