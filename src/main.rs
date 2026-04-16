mod cli;
mod identity;

use anyhow;
use clap::Parser;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    match cli.command {
        cli::Commands::Identity(args) => identity::dispatch(args)?,
    }

    Ok(())
}
