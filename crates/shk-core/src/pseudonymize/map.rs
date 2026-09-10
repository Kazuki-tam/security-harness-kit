use super::apply::RestoreMapDocument;
use super::derive::{KeyMaterial, derive_info_key};
use anyhow::{Context, Result, bail};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroize;

const MAGIC: &[u8; 6] = b"SHKMAP";
const VERSION: u8 = 1;
const MAP_INFO: &str = "shk/pseudonymize/v1/map";

pub fn encrypt_map(material: &KeyMaterial, document: &RestoreMapDocument) -> Result<Vec<u8>> {
    let plaintext = serde_json::to_vec(document).context("serialize restore map")?;
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
    let plaintext = cipher
        .decrypt(&nonce, &bytes[19..])
        .map_err(|_| anyhow::anyhow!("decrypt restore map (wrong key or corrupt file)"))?;
    serde_json::from_slice(&plaintext).context("parse restore map document")
}

pub fn restore_text(input: &str, document: &RestoreMapDocument) -> (String, usize, usize) {
    let mut out = input.to_string();
    let mut replacements = 0usize;
    let mut multi_original = 0usize;
    let mut entries = document.entries.clone();
    entries.sort_by(|a, b| b.token.len().cmp(&a.token.len()));
    for entry in entries {
        if entry.originals.is_empty() || !out.contains(&entry.token) {
            continue;
        }
        if entry.originals.len() > 1 {
            multi_original += 1;
        }
        let original = &entry.originals[0];
        replacements += out.matches(&entry.token).count();
        out = out.replace(&entry.token, original);
    }
    (out, replacements, multi_original)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pseudonymize::apply::{MapCollector, RestoreMapEntry};

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
}
