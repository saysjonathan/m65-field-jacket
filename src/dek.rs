use rand::prelude::*;
use secrecy::{ExposeSecret, SecretBox};

pub struct Dek(SecretBox<[u8; Self::BYTES]>);

impl Dek {
    pub const BYTES: usize = 32;

    pub fn new(bytes: [u8; Self::BYTES]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    pub fn new_random() -> Self {
        let mut bytes = [0u8; Self::BYTES];
        rand::rng().fill_bytes(&mut bytes);
        Self::new(bytes)
    }

    pub fn from_bytes(bytes: [u8: Self::BYTES]) -> anyhow::Result<Self> {
        let arr: [u8; Self::BYTES] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("DEK is not {} bytes", Self::BYTES))?;
        Ok(Self::new(arr))
    }

    pub fn expose(&self) -> &[u8; Self::BYTES] {
        self.0.expose_secret()
    }
}
