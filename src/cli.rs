use crate::domain::name::{EnvSecretName, FileSecretName, IdentityName, PocketName};
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
    Set(SetArgs),
    List {
        pocket: PocketName,
    },
    Get {
        pocket: PocketName,
        name: String,
    },
    Remove {
        pocket: PocketName,
        name: String,
    },
    Lock {
        pocket: Option<PocketName>,
    },
    Unlock {
        pocket: PocketName,
    },
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
        name: IdentityName,

        #[arg(short = 'd', long)]
        set_default: bool,
    },

    Default {},

    SetDefault {
        #[arg(value_name = "NAME")]
        name: IdentityName,
    },

    Show {
        #[arg(value_name = "NAME", default_value = "default")]
        name: IdentityName,
    },

    List {},

    Remove {
        #[arg(value_name = "NAME")]
        name: IdentityName,
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
        name: PocketName,
    },

    List {},

    Remove {
        #[arg(value_name = "NAME")]
        name: PocketName,
    },
}

#[derive(Debug, Args)]
pub struct SetArgs {
    #[command(subcommand)]
    pub command: SetCommands,
}

#[derive(Debug, Subcommand)]
pub enum SetCommands {
    Env {
        pocket: PocketName,
        name: EnvSecretName,
        value: String,
    },

    File {
        pocket: PocketName,
        source: String,
        target: Option<String>,
        #[arg(short = 'n', long)]
        name: Option<FileSecretName>,
    },
}
