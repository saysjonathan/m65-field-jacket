use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "mfj", version, about, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(arg_required_else_help = true)]
    Identity(IdentityArgs),
    Pocket(PocketArgs),
}

#[derive(Debug, Args)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub command: IdentityCommands,
}

#[derive(Debug, Subcommand)]
pub enum IdentityCommands {
    Init {
        #[arg(value_name = "NAME", default_value = "default")]
        name: String,

        #[arg(short = 'd', long)]
        set_default: bool,
    },

    Default {},

    SetDefault {
        #[arg(value_name = "NAME")]
        name: String,
    },

    Show {
        #[arg(value_name = "NAME", default_value = "default")]
        name: String,
    },

    List {},

    Remove {
        #[arg(value_name = "NAME")]
        name: String,
    },
}

#[derive(Debug, Args)]
pub struct PocketArgs {
    #[command(subcommand)]
    pub command: PocketCommands,
}

#[derive(Debug, Subcommand)]
pub enum PocketCommands {
    Init {
        #[arg(value_name = "NAME")]
        name: String,
    },
}
