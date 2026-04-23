use crate::dek::Dek;
use crate::pocket::{Locked, Pocket};
use crate::stanza::MfjMetadata;
use age_core::format::Stanza;
use anyhow::Context;
use std::io::Write;
use std::path::Path;

pub struct Keyring {
    bytes: Vec<u8>,
}

impl Keyring {
    pub fn create(recipient: &age::x25519::Recipient) -> anyhow::Result<(Self, Dek)> {
        let dek = Dek::new_random();
        let metadata = MfjMetadata(vec![Stanza {
            tag: "mfj-version".to_owned(),
            args: vec!["1".to_owned()],
            body: vec![],
        }]);

        let encryptor = age::Encryptor::with_recipients(
            [
                &metadata as &dyn age::Recipient,
                recipient as &dyn age::Recipient,
            ]
            .into_iter(),
        )?;

        let mut bytes = Vec::new();
        let mut w = encryptor.wrap_output(&mut bytes)?;
        w.write_all(dek.expose())?;
        w.finish()?;

        Ok((Self { bytes }, dek))
    }

    pub fn load(pocket: &Pocket<Locked>) -> anyhow::Result<Self> {
        let bytes = std::fs::read(pocket.keyring_path()).with_context(|| {
            format!(
                "failed to read keyring for pocket: {}",
                pocket.dir().display()
            )
        })?;
        Ok(Self { bytes })
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        std::fs::write(dir.join("keyring"), &self.bytes)
            .with_context(|| format!("failed to write keyring for pocket: {}", dir.display()))
    }

    pub fn decrypt_dek(&self, identity: &dyn age::Identity) -> anyhow::Result<Dek> {
        let decryptor = age::Decryptor::new(&self.bytes[..])?;
        let mut dek_vec = Vec::new();
        let mut reader = decryptor.decrypt(std::iter::once(identity))?;
        std::io::Read::read_to_end(&mut reader, &mut dek_vec)?;
        Dek::from_bytes(&dek_vec)
    }
}
