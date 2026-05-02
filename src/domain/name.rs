use anyhow::{Error, Result, bail};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;

pub type PocketName = Name<Pocket>;
pub type IdentityName = Name<Identity>;
pub type EnvSecretName = Name<EnvSecret>;
pub type FileSecretName = Name<FileSecret>;

pub trait NameRules {
    const KIND: &'static str;
    const MAX_LEN: usize;
    fn validate(s: &str) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pocket;

impl NameRules for Pocket {
    const KIND: &'static str = "pocket";
    const MAX_LEN: usize = 64;

    fn validate(s: &str) -> Result<()> {
        if !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            bail!("pocket name must match [a-z0-9-]");
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity;

impl NameRules for Identity {
    const KIND: &'static str = "identity";
    const MAX_LEN: usize = 64;

    fn validate(s: &str) -> Result<()> {
        if !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            bail!("identity name must match [a-z0-9-]");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvSecret;

impl NameRules for EnvSecret {
    const KIND: &'static str = "env secret";
    const MAX_LEN: usize = 256;

    fn validate(s: &str) -> Result<()> {
        if s.starts_with(|c: char| c.is_ascii_digit()) {
            bail!("env secret name must not start with a digit");
        }

        if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            bail!("env secret name must match [A-Za-z_][A-Za-z0-9_]*");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileSecret;

impl NameRules for FileSecret {
    const KIND: &'static str = "file secret";
    const MAX_LEN: usize = 256;

    fn validate(s: &str) -> Result<()> {
        for c in s.chars() {
            match c {
                '/' | '\\' | '\0' => {
                    bail!("file secret name must not contain {c:?}")
                }
                c if c.is_control() => {
                    bail!("file secret name must not contain control characters")
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name<K: NameRules>(String, PhantomData<K>);

impl<K: NameRules> Name<K> {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<K: NameRules> FromStr for Name<K> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("{} name must not be empty", K::KIND);
        }

        if s.len() > K::MAX_LEN {
            bail!("{} name must be <= {} characters", K::KIND, K::MAX_LEN);
        }

        K::validate(s)?;
        Ok(Self(s.to_owned(), PhantomData))
    }
}

impl<K: NameRules> Display for Name<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<K: NameRules> AsRef<str> for Name<K> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<K: NameRules> Serialize for Name<K> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de, K: NameRules> Deserialize<'de> for Name<K> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<Self>().map_err(serde::de::Error::custom)
    }
}
