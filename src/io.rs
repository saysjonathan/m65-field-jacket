use anyhow::Result;
use std::io::Write;

pub trait PassphraseSource {
    fn read(&self, prompt: &str) -> Result<String>;
}

pub trait Confirm {
    fn confirm(&self, prompt: &str, expected: &str) -> Result<bool>;
}

pub struct TtyPrompt;

impl PassphraseSource for TtyPrompt {
    fn read(&self, prompt: &str) -> Result<String> {
        Ok(rpassword::prompt_password(prompt)?)
    }
}

pub struct TtyConfirm;

impl Confirm for TtyConfirm {
    fn confirm(&self, prompt: &str, expected: &str) -> Result<bool> {
        eprint!("{prompt}");
        std::io::stderr().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(input.trim() == expected)
    }
}
