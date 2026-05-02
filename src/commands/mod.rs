pub mod identity;
pub mod pocket;
pub mod secret;

use crate::config::Config;
use crate::io::{Confirm, PassphraseSource};

pub struct Ctx {
    pub config: Option<Config>,
    pub passphrase: Box<dyn PassphraseSource>,
    pub confirm: Box<dyn Confirm>,
}
