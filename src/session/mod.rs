mod store;
use crate::config::Config;
use crate::domain::dek::Dek;
use store::SessionRecord;

pub fn try_resume(pocket_key: &str) -> anyhow::Result<Option<Dek>> {
    Ok(SessionRecord::resume()?.get(pocket_key))
}

pub fn establish(pocket_key: &str, dek: &Dek, config: &Config) -> anyhow::Result<()> {
    let mut record = SessionRecord::resume()?;
    record.insert(pocket_key, dek, config.session_ttl_seconds);
    record.seal()
}

pub fn invalidate_pocket(pocket_key: &str) -> anyhow::Result<()> {
    let mut record = SessionRecord::resume()?;
    if !record.invalidate(pocket_key) {
        return Ok(());
    }

    if record.is_empty() {
        SessionRecord::remove()
    } else {
        record.seal()
    }
}

pub fn invalidate_all() -> anyhow::Result<()> {
    SessionRecord::remove()
}
