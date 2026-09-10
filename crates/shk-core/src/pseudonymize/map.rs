use super::apply::{RestoreMapDocument, RestoreMapEntry};
use super::derive::{KeyMaterial, derive_info_key};
use anyhow::{Context, Result, bail};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::collections::{BTreeSet, HashMap};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 6] = b"SHKMAP";
const VERSION: u8 = 1;
const MAP_INFO: &str = "shk/pseudonymize/v1/map";

pub fn encrypt_map(material: &KeyMaterial, document: &RestoreMapDocument) -> Result<Vec<u8>> {
    let plaintext = Zeroizing::new(serde_json::to_vec(document).context("serialize restore map")?);
    let mut key_bytes = derive_info_key(material, MAP_INFO)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|_| anyhow::anyhow!("invalid map cipher key"))?;
    key_bytes.zeroize();
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|err| anyhow::anyhow!("generate map nonce: {err}"))?;
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| anyhow::anyhow!("encrypt restore map"))?;
    let mut out = Vec::with_capacity(6 + 1 + 12 + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_map(material: &KeyMaterial, bytes: &[u8]) -> Result<RestoreMapDocument> {
    if bytes.len() < 19 || &bytes[..6] != MAGIC {
        bail!("not an encrypted .shk-map file");
    }
    if bytes[6] != VERSION {
        bail!("unsupported .shk-map version {}", bytes[6]);
    }
    let nonce = Nonce::from(*<&[u8; 12]>::try_from(&bytes[7..19]).expect("nonce length"));
    let mut key_bytes = derive_info_key(material, MAP_INFO)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|_| anyhow::anyhow!("invalid map cipher key"))?;
    key_bytes.zeroize();
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(&nonce, &bytes[19..])
            .map_err(|_| anyhow::anyhow!("decrypt restore map (wrong key or corrupt file)"))?,
    );
    let document: RestoreMapDocument =
        serde_json::from_slice(&plaintext).context("parse restore map document")?;
    if document.version != 1 {
        bail!("unsupported restore map document version");
    }
    super::validate_norm(&document.norm).map_err(anyhow::Error::msg)?;
    Ok(document)
}

/// Restore outcome for one text unit: rewritten text, replacement count, and
/// how many distinct tokens carried more than one original.
pub type RestoreOutcome = (String, usize, usize);

/// Token lookup built once per restore map and reused across fields, groups,
/// or files. Matching is longest-token-first at every position; tokens are not
/// boundary-checked because both `email_ab` and `email_abcd` may legitimately
/// exist when maps from different `token_bits` runs were merged.
pub struct TokenIndex<'a> {
    by_token: HashMap<&'a str, &'a RestoreMapEntry>,
    /// Distinct token lengths, longest first.
    lengths: Vec<usize>,
}

impl<'a> TokenIndex<'a> {
    pub fn new(document: &'a RestoreMapDocument) -> Self {
        let mut by_token = HashMap::new();
        let mut lengths = BTreeSet::new();
        for entry in &document.entries {
            if entry.token.is_empty() || entry.originals.is_empty() {
                continue;
            }
            by_token.insert(entry.token.as_str(), entry);
            lengths.insert(entry.token.len());
        }
        Self {
            by_token,
            lengths: lengths.into_iter().rev().collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.by_token.is_empty()
    }

    pub fn restore(&self, input: &str) -> RestoreOutcome {
        if self.is_empty() {
            return (input.to_string(), 0, 0);
        }
        let mut out = String::with_capacity(input.len());
        let mut replacements = 0usize;
        let mut ambiguous = BTreeSet::new();
        let mut remaining = input;
        let mut previous = None;
        while !remaining.is_empty() {
            if let Some(entry) = self.match_at(remaining, previous) {
                out.push_str(&entry.originals[0]);
                remaining = &remaining[entry.token.len()..];
                replacements += 1;
                if entry.originals.len() > 1 {
                    ambiguous.insert(entry.token.as_str());
                }
                previous = entry.originals[0].chars().next_back();
                continue;
            }
            let ch = remaining.chars().next().expect("nonempty input");
            out.push(ch);
            remaining = &remaining[ch.len_utf8()..];
            previous = Some(ch);
        }
        (out, replacements, ambiguous.len())
    }

    fn match_at(&self, remaining: &str, previous: Option<char>) -> Option<&'a RestoreMapEntry> {
        // Tokens are ASCII, so a non-ASCII lead byte can never start one.
        if !remaining.as_bytes()[0].is_ascii_lowercase()
            || previous.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return None;
        }
        self.lengths.iter().find_map(|&len| {
            remaining
                .get(..len)
                .and_then(|candidate| self.by_token.get(candidate).copied())
                .filter(|entry| {
                    let tail = &remaining[entry.token.len()..];
                    !tail.as_bytes().first().is_some_and(|byte| {
                        byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7')
                    }) || self.starts_with_known_token(tail)
                })
        })
    }

    fn starts_with_known_token(&self, input: &str) -> bool {
        self.lengths.iter().any(|&len| {
            input
                .get(..len)
                .is_some_and(|candidate| self.by_token.contains_key(candidate))
        })
    }
}

pub fn restore_text(input: &str, document: &RestoreMapDocument) -> RestoreOutcome {
    TokenIndex::new(document).restore(input)
}

/// Restore fields before serializing so commas, quotes and newlines remain data.
pub fn restore_table(
    input: &str,
    document: &RestoreMapDocument,
    delimiter: u8,
) -> Result<RestoreOutcome> {
    let index = TokenIndex::new(document);
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .has_headers(false)
        .flexible(true)
        .from_reader(input.as_bytes());
    let mut writer = csv::WriterBuilder::new()
        .delimiter(delimiter)
        .flexible(true)
        .terminator(if input.contains("\r\n") {
            csv::Terminator::CRLF
        } else {
            csv::Terminator::Any(b'\n')
        })
        .from_writer(Vec::new());
    let mut count = 0;
    let mut multi = 0;
    for row in reader.records() {
        let row = row.context("read pseudonymized table")?;
        let restored: Vec<_> = row
            .iter()
            .map(|field| {
                let (value, n, m) = index.restore(field);
                count += n;
                multi += m;
                value
            })
            .collect();
        writer.write_record(restored)?;
    }
    let bytes = writer.into_inner().context("finish restored table")?;
    Ok((String::from_utf8(bytes)?, count, multi))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pseudonymize::apply::MapCollector;

    #[test]
    fn restore_does_not_reprocess_originals_and_quotes_table_fields() {
        let document = RestoreMapDocument {
            entries: vec![
                RestoreMapEntry {
                    token: "name_abcdef".into(),
                    kind: "name".into(),
                    originals: vec!["name_ab, \"quoted\"\nnext".into()],
                },
                RestoreMapEntry {
                    token: "name_ab".into(),
                    kind: "name".into(),
                    originals: vec!["second".into()],
                },
            ],
            ..Default::default()
        };
        let original = &document.entries[0].originals[0];
        assert_eq!(
            restore_text("name_abcdef", &document),
            (original.clone(), 1, 0)
        );
        let (table, count, _) =
            restore_table("value,other\nname_abcdef,ok\n", &document, b',').unwrap();
        let record = csv::Reader::from_reader(table.as_bytes())
            .records()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(&record[0], original);
        assert_eq!(&record[1], "ok");
        assert_eq!(count, 1);
    }

    #[test]
    fn map_round_trip_and_restore() {
        let material = KeyMaterial::from_parts([0x55; 32], [0x66; 32]);
        let mut collector = MapCollector::default();
        collector.record(
            "email_abc".into(),
            &crate::pseudonymize::Kind::Email,
            "Ada".into(),
        );
        collector.record(
            "email_abc".into(),
            &crate::pseudonymize::Kind::Email,
            "ada".into(),
        );
        let doc = collector.into_document("v1".into(), material.fingerprint());
        let encrypted = encrypt_map(&material, &doc).unwrap();
        assert!(encrypted.starts_with(b"SHKMAP"));
        let parsed = decrypt_map(&material, &encrypted).unwrap();
        assert_eq!(parsed.key_fingerprint, material.fingerprint());
        let (restored, count, multi) = restore_text("see email_abc please", &parsed);
        assert_eq!(restored, "see Ada please");
        assert_eq!(count, 1);
        assert_eq!(multi, 1);
        let other = KeyMaterial::from_parts([0x01; 32], [0x02; 32]);
        assert!(decrypt_map(&other, &encrypted).is_err());
    }

    #[test]
    fn restore_handles_multibyte_neighbours_and_unknown_prefixes() {
        let doc = RestoreMapDocument {
            version: 1,
            norm: "v1".into(),
            key_fingerprint: "x".into(),
            entries: vec![RestoreMapEntry {
                token: "email_abcd".into(),
                kind: "email".into(),
                originals: vec!["ada".into()],
            }],
        };
        let (restored, count, _) = restore_text("宛先はemail_abcdです。email_abcx", &doc);
        assert_eq!(restored, "宛先はadaです。email_abcx");
        assert_eq!(count, 1);
        let empty = RestoreMapDocument::default();
        assert_eq!(
            restore_text("email_abcd", &empty),
            ("email_abcd".into(), 0, 0)
        );
    }

    #[test]
    fn table_pseudonymize_then_restore_round_trips() {
        use crate::pseudonymize::{NormalizeSettings, TableOptions, parse_columns_spec, run_table};
        let material = KeyMaterial::from_parts([0x0a; 32], [0x0b; 32]);
        let options = TableOptions {
            delimiter: b',',
            no_header: false,
            token_bits: 64,
            norm: "v1".into(),
            settings: NormalizeSettings::default(),
            config_columns: Default::default(),
            cli_columns: Some(parse_columns_spec("Email:email,Name:name").unwrap()),
            dry_run: false,
            crlf: false,
            shk_version: "test".into(),
            key_namespace: "test".into(),
        };
        let email = ["ada", "@", "example.com"].concat();
        let input = format!("Email,Name,Note\n{email},\"Lovelace, Ada\",keep\n");
        let mut collector = MapCollector::default();
        let mut out = Vec::new();
        run_table(
            input.as_bytes(),
            Some(&mut out),
            &options,
            Some(&material),
            Some(&mut collector),
        )
        .unwrap();
        let pseudo = String::from_utf8(out).unwrap();
        assert!(!pseudo.contains("Lovelace"), "{pseudo}");
        let doc = collector.into_document("v1".into(), material.fingerprint());
        let doc = decrypt_map(&material, &encrypt_map(&material, &doc).unwrap()).unwrap();
        let (restored, count, multi) = restore_table(&pseudo, &doc, b',').unwrap();
        assert_eq!(restored, input);
        assert_eq!((count, multi), (2, 0));
    }

    #[test]
    fn rejects_corrupt_map_files_and_keeps_crlf_tables() {
        let material = KeyMaterial::from_parts([0x55; 32], [0x66; 32]);
        let doc = MapCollector::default().into_document("v1".into(), material.fingerprint());
        let mut encrypted = encrypt_map(&material, &doc).unwrap();
        assert!(decrypt_map(&material, b"short").is_err());
        assert!(decrypt_map(&material, b"NOTMAP\x01xxxxxxxxxxxxxxxxx").is_err());
        encrypted[6] = 9;
        assert!(
            decrypt_map(&material, &encrypted)
                .unwrap_err()
                .to_string()
                .contains("version")
        );

        let doc = RestoreMapDocument {
            entries: vec![RestoreMapEntry {
                token: "email_abcd".into(),
                kind: "email".into(),
                originals: vec!["ada".into()],
            }],
            ..Default::default()
        };
        let (table, count, _) = restore_table("a,b\r\nemail_abcd,x\r\n", &doc, b',').unwrap();
        assert_eq!(table, "a,b\r\nada,x\r\n");
        assert_eq!(count, 1);
    }

    #[test]
    fn restore_prefers_longer_tokens() {
        let doc = RestoreMapDocument {
            version: 1,
            norm: "v1".into(),
            key_fingerprint: "x".into(),
            entries: vec![
                RestoreMapEntry {
                    token: "email_ab".into(),
                    kind: "email".into(),
                    originals: vec!["short".into()],
                },
                RestoreMapEntry {
                    token: "email_abcd".into(),
                    kind: "email".into(),
                    originals: vec!["long".into()],
                },
            ],
        };
        let (restored, _, _) = restore_text("email_abcd and email_ab", &doc);
        assert_eq!(restored, "long and short");
    }

    #[test]
    fn restore_leaves_unknown_longer_and_embedded_tokens_unchanged() {
        let doc = RestoreMapDocument {
            version: 1,
            norm: "v1".into(),
            key_fingerprint: "x".into(),
            entries: vec![RestoreMapEntry {
                token: "email_abcdefghijklm".into(),
                kind: "email".into(),
                originals: vec!["restored".into()],
            }],
        };
        let input = "email_abcdefghijklmnop fooemail_abcdefghijklm";
        assert_eq!(restore_text(input, &doc), (input.to_string(), 0, 0));
        assert_eq!(
            restore_text("(email_abcdefghijklm)", &doc),
            ("(restored)".into(), 1, 0)
        );
    }
}
