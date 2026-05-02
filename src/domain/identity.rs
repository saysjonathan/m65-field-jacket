use crate::crypto;
use crate::domain::name::IdentityName;
use crate::io::PassphraseSource;
use crate::storage;
use anyhow::Context;
use secrecy::ExposeSecret;

pub struct Locked;
pub struct Unlocked {
    inner: age::x25519::Identity,
}

pub struct Identity<S> {
    name: IdentityName,
    state: S,
}

impl<S> Identity<S> {
    pub fn name(&self) -> &IdentityName {
        &self.name
    }

    pub fn recipient(&self) -> anyhow::Result<age::x25519::Recipient> {
        let path = storage::identity_public(self.name().as_str())?;
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("identity pubkey not found: {}", self.name()))?;

        contents
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid public key: {e}"))
    }
}

impl Identity<Locked> {
    pub fn open(name: &IdentityName) -> anyhow::Result<Self> {
        let path = storage::identity_private(name.as_str())?;
        if !path.exists() {
            anyhow::bail!("identity does not exist: {}", name);
        }
        Ok(Self {
            name: name.to_owned(),
            state: Locked,
        })
    }

    pub fn unlock(self, passphrase: &dyn PassphraseSource) -> anyhow::Result<Identity<Unlocked>> {
        let path = storage::identity_private(self.name().as_str())?;
        let blob =
            std::fs::read(&path).with_context(|| format!("identity not found: {}", self.name()))?;

        let (salt, rest) = blob
            .split_first_chunk::<{ crypto::SALT_LEN }>()
            .ok_or_else(|| anyhow::anyhow!("malformed identity blob: salt"))?;

        let (nonce, ciphertext) = rest
            .split_first_chunk::<{ crypto::NONCE_LEN }>()
            .ok_or_else(|| anyhow::anyhow!("malformed identity blob: nonce"))?;

        let pass = passphrase
            .read("Passphrase: ")
            .context("failed to read passphrase")?;

        let kek = crypto::derive_kek(pass.as_bytes(), salt)?;
        let plaintext = crypto::decrypt(kek.expose_secret(), nonce, ciphertext)?;

        let key_str = std::str::from_utf8(&plaintext).context("decrypted key not valid UTF-8")?;
        let inner = key_str
            .parse::<age::x25519::Identity>()
            .map_err(|e| anyhow::anyhow!("invalid age private key: {e}"))?;

        Ok(Identity {
            name: self.name,
            state: Unlocked { inner },
        })
    }

    pub fn create(
        name: &IdentityName,
        passphrase: &dyn PassphraseSource,
    ) -> anyhow::Result<(Self, age::x25519::Recipient)> {
        let identities_dir = storage::identities_dir()?;
        std::fs::create_dir_all(&identities_dir).context("failed to create ~/.m65/identities")?;

        let identity_path = storage::identity_private(name.as_str())?;
        let pub_path = storage::identity_public(name.as_str())?;

        if identity_path.exists() {
            anyhow::bail!("identity already exists: {name}");
        }

        let key = age::x25519::Identity::generate();
        let pubkey = key.to_public();

        let pass = passphrase
            .read("Passphrase: ")
            .context("failed to read passphrase")?;
        let conf = passphrase
            .read("Confirm passphrase: ")
            .context("failed to read password confirmation")?;
        if pass != conf {
            anyhow::bail!("passphrases do not match");
        }

        let salt = crypto::random_salt();
        let kek = crypto::derive_kek(pass.as_bytes(), &salt)?;

        let key_str = key.to_string();
        let plaintext = key_str.expose_secret().as_bytes();

        let nonce_bytes = crypto::random_nonce();
        let ciphertext = crypto::encrypt(kek.expose_secret(), &nonce_bytes, plaintext)?;

        let mut blob = Vec::with_capacity(crypto::SALT_LEN + crypto::NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        std::fs::write(&identity_path, &blob)?;
        std::fs::write(&pub_path, &pubkey.to_string())?;

        Ok((
            Self {
                name: name.to_owned(),
                state: Locked,
            },
            pubkey,
        ))
    }

    pub fn list() -> anyhow::Result<Vec<Self>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(storage::identities_dir()?)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("pub") {
                continue;
            }
            if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                if let Ok(name) = name.parse::<IdentityName>() {
                    out.push(Self {
                        name: name.to_owned(),
                        state: Locked,
                    });
                }
            }
        }
        Ok(out)
    }

    pub fn delete(self) -> anyhow::Result<()> {
        std::fs::remove_file(storage::identity_private(self.name().as_str())?)?;
        std::fs::remove_file(storage::identity_public(self.name().as_str())?)?;
        Ok(())
    }
}

impl Identity<Unlocked> {
    pub fn as_age(&self) -> &dyn age::Identity {
        &self.state.inner
    }
}
