use age_core::format::{FileKey, Stanza};
use std::collections::HashSet;
use std::io::BufRead;

pub struct MfjMetadata(pub Vec<Stanza>);

impl age::Recipient for MfjMetadata {
    fn wrap_file_key(
        &self,
        _: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        Ok((
            self.0
                .iter()
                .map(|s| Stanza {
                    tag: s.tag.clone(),
                    args: s.args.clone(),
                    body: s.body.clone(),
                })
                .collect(),
            HashSet::new(),
        ))
    }
}

pub fn read_stanzas(r: impl BufRead) -> anyhow::Result<Vec<Stanza>> {
    let mut out = vec![];
    for line in r.lines().skip(1) {
        let line = line?;
        if line == "---" {
            break;
        }
        if let Some(rest) = line.strip_prefix("-> ") {
            let mut parts = rest.split(": ");
            let tag = parts.next().unwrap_or("").to_owned();
            if tag.starts_with("mfj-") {
                out.push(Stanza {
                    tag,
                    args: parts.map(str::to_owned).collect(),
                    body: vec![],
                });
            }
        }
    }

    Ok(out)
}
