use super::UNPARSED;
use super::derive::{KeyMaterial, token};
use super::kind::Kind;
use super::normalize::{NormalizeOutcome, NormalizeSettings, normalize_value};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestoreMapDocument {
    pub version: u8,
    pub norm: String,
    pub key_fingerprint: String,
    pub entries: Vec<RestoreMapEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreMapEntry {
    pub token: String,
    pub kind: String,
    pub originals: Vec<String>,
}

#[derive(Debug, Default)]
pub struct MapCollector {
    entries: BTreeMap<String, RestoreMapEntry>,
}

impl MapCollector {
    pub fn record(&mut self, token: String, kind: &Kind, original: String) {
        self.entry_for(token, kind.as_config_value())
            .push_original(original);
    }

    fn entry_for(&mut self, token: String, kind: String) -> &mut RestoreMapEntry {
        self.entries
            .entry(token.clone())
            .or_insert_with(|| RestoreMapEntry {
                token,
                kind,
                originals: Vec::new(),
            })
    }

    pub fn into_document(self, norm: String, key_fingerprint: String) -> RestoreMapDocument {
        RestoreMapDocument {
            version: 1,
            norm,
            key_fingerprint,
            entries: self.entries.into_values().collect(),
        }
    }

    pub fn merge(&mut self, other: RestoreMapDocument) {
        for mut entry in other.entries {
            let token = std::mem::take(&mut entry.token);
            let kind = std::mem::take(&mut entry.kind);
            let dest = self.entry_for(token, kind);
            for original in entry.originals.drain(..) {
                dest.push_original(original);
            }
        }
    }
}

impl RestoreMapEntry {
    fn push_original(&mut self, original: String) {
        if !self.originals.contains(&original) {
            self.originals.push(original);
        }
    }
}

impl Drop for RestoreMapEntry {
    fn drop(&mut self) {
        self.token.zeroize();
        self.kind.zeroize();
        self.originals.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellAction {
    Keep,
    Unparsed,
    Token(String),
}

pub fn apply_cell(
    kind: &Kind,
    raw: &str,
    material: &KeyMaterial,
    settings: NormalizeSettings,
    token_bits: u16,
    map: Option<&mut MapCollector>,
) -> Result<CellAction> {
    match normalize_value(kind, raw, settings) {
        NormalizeOutcome::Missing => Ok(CellAction::Keep),
        NormalizeOutcome::Unparsed => Ok(CellAction::Unparsed),
        NormalizeOutcome::Value(normalized) => {
            let value = token(material, kind, &normalized, token_bits)?;
            if let Some(map) = map {
                map.record(value.clone(), kind, raw.to_string());
            }
            Ok(CellAction::Token(value))
        }
    }
}

pub fn replacement_text(action: &CellAction, original: &str) -> String {
    match action {
        CellAction::Keep => original.to_string(),
        CellAction::Unparsed => UNPARSED.to_string(),
        CellAction::Token(token) => token.clone(),
    }
}

pub fn builtin_rule_kind(rule_id: &str) -> Option<Kind> {
    match rule_id {
        "pii.email" => Some(Kind::Email),
        "pii.en.phone" | "pii.ja.phone" => Some(Kind::Phone),
        "pii.en.name" | "pii.ja.name" => Some(Kind::Name),
        _ => None,
    }
}

pub fn resolve_rule_kind(
    rule_id: &str,
    overrides: &BTreeMap<String, String>,
) -> Result<Option<Kind>, String> {
    if let Some(raw) = overrides.get(rule_id) {
        return Kind::parse(raw).map(Some).map_err(|err| err.0);
    }
    Ok(builtin_rule_kind(rule_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_map_to_kinds_and_keep_passes_through() {
        assert_eq!(builtin_rule_kind("pii.ja.phone"), Some(Kind::Phone));
        assert_eq!(builtin_rule_kind("pii.en.name"), Some(Kind::Name));
        assert_eq!(builtin_rule_kind("pii.credit_card"), None);
        assert_eq!(replacement_text(&CellAction::Keep, "raw"), "raw");
        let mut overrides = BTreeMap::new();
        overrides.insert("pii.credit_card".to_string(), "custom:card".to_string());
        assert_eq!(
            resolve_rule_kind("pii.credit_card", &overrides).unwrap(),
            Some(Kind::Custom("card".into()))
        );
    }
}
