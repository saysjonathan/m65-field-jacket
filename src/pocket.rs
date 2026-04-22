use crate::cli::{PocketArgs, PocketCommands};
use crate::config::Config;
use crate::identity::decrypt_identity;
use crate::paths::{identities_dir, pocket_dir};
use crate::stanza;
use age_core::format::Stanza;
use anyhow::Context;
use rand::prelude::*;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn dispatch(args: PocketArgs, config: Option<Config>) -> anyhow::Result<()> {
    match args.command {
        PocketCommands::Init { name } => init(name, config),
        PocketCommands::List {} => list(),
        PocketCommands::Remove { name } => remove(name),
    }
}

pub fn validate_pocket(pocket: &str) -> anyhow::Result<PathBuf> {
    let pocket_dir = pocket_dir(pocket)?;
    match pocket_dir.exists() {
        true => Ok(pocket_dir),
        false => anyhow::bail!(
            "pocket not initialized: {}. run `mfj pocket init` to create",
            pocket
        ),
    }
}

pub fn decrypt_dek(pocket_dir: &Path, config: &Config) -> anyhow::Result<[u8; 32]> {
    let id = decrypt_identity(&config.default_identity)?;
    let keyring_bytes = std::fs::read(pocket_dir.join("keyring"))?;
    let decryptor = age::Decryptor::new(&keyring_bytes[..])?;
    let mut dek = Vec::new();
    let mut reader = decryptor.decrypt(std::iter::once(&id as &dyn age::Identity))?;
    std::io::Read::read_to_end(&mut reader, &mut dek)?;
    dek.try_into()
        .map_err(|_| anyhow::anyhow!("DEK is not 32 bytes"))
}

fn init(name: String, config: Option<Config>) -> anyhow::Result<()> {
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        anyhow::bail!("pocket name must be alphanumeric");
    }

    if name.len() > 64 {
        anyhow::bail!("pocket name must be <=64 chars");
    }

    let c = Config::require(config)?;

    let pubkey_path = identities_dir()?.join(format!("{}.pub", c.default_identity));
    let pubkey = std::fs::read_to_string(&pubkey_path)
        .with_context(|| format!("identity not found: {}", c.default_identity));
    let recipient: age::x25519::Recipient = pubkey?
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid public key: {e}"))?;

    let mut dek = [0u8; 32];
    rand::rng().fill_bytes(&mut dek);

    let metadata = stanza::MfjMetadata(vec![Stanza {
        tag: "mfj-version".to_owned(),
        args: vec!["1".to_owned()],
        body: vec![],
    }]);

    let encryptor = age::Encryptor::with_recipients(
        [
            &metadata as &dyn age::Recipient,
            &recipient as &dyn age::Recipient,
        ]
        .into_iter(),
    )?;

    let mut keyring = Vec::new();
    let mut w = encryptor.wrap_output(&mut keyring)?;
    w.write_all(&dek)?;
    w.finish()?;

    let pocket_dir = pocket_dir(&name)?;
    if pocket_dir.exists() {
        anyhow::bail!("pocket already exists: {}", name);
    }
    std::fs::create_dir_all(&pocket_dir)
        .with_context(|| format!("failed to create {}", pocket_dir.display()))?;

    std::fs::write(pocket_dir.join("keyring"), &keyring)?;

    let tmp_dir = pocket_dir.join(".tmp");
    std::fs::create_dir(&tmp_dir)
        .with_context(|| format!("failed to create temp dir {}", tmp_dir.display()))?;

    Ok(())
}

fn list() -> anyhow::Result<()> {
    for entry in std::fs::read_dir(".m65")? {
        println!("{}", entry?.file_name().to_string_lossy());
    }

    Ok(())
}

fn remove(name: String) -> anyhow::Result<()> {
    let pocket_dir = validate_pocket(&name)?;

    print!("Type the pocket name to confirm removal: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    if input.trim() != name {
        anyhow::bail!("name did not match; aborting");
    }

    std::fs::remove_dir_all(pocket_dir)?;
    println!("removed pocket: {}", name);

    Ok(())
}
