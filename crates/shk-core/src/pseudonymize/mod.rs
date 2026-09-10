//! Deterministic local-first pseudonymization (Phase 1b: table, text, maps).

mod apply;
mod columns;
mod derive;
mod kind;
mod map;
mod normalize;
mod table;
mod text;
mod xlsx;

pub use apply::{
    CellAction, MapCollector, RestoreMapDocument, apply_cell, replacement_text, resolve_rule_kind,
};
pub use columns::{
    ColumnOverrides, ColumnSource, ResolvedColumn, infer_header, parse_columns_spec,
    resolve_columns,
};
pub use derive::{KeyMaterial, fingerprint, parse_stored_material, token};
pub use kind::{Kind, ParseKindError};
pub use map::{RestoreOutcome, TokenIndex, decrypt_map, encrypt_map, restore_table, restore_text};
pub use normalize::{NormalizeOutcome, NormalizeSettings, is_missing_raw, normalize_value};
pub use table::{
    MetaColumn, PseudonymizeMeta, TableOptions, TableResult, delimiter_for_path, run_table,
};
pub use text::{TextOptions, TextResult, run_office_text, run_text};
pub use xlsx::run_xlsx;

pub const NORM_V1: &str = "v1";
pub const UNPARSED: &str = "[UNPARSED]";
pub const MIN_TOKEN_BITS: u16 = 64;
pub const MAX_TOKEN_BITS: u16 = 128;
pub const INFER_SAMPLE_ROWS: usize = 20;
pub const INFER_MATCH_THRESHOLD: f64 = 0.60;

pub fn validate_token_bits(token_bits: u16) -> Result<(), String> {
    if !(MIN_TOKEN_BITS..=MAX_TOKEN_BITS).contains(&token_bits) || !token_bits.is_multiple_of(8) {
        return Err(format!(
            "token_bits must be a multiple of 8 between {MIN_TOKEN_BITS} and {MAX_TOKEN_BITS}"
        ));
    }
    Ok(())
}

pub fn validate_norm(norm: &str) -> Result<(), String> {
    if norm != NORM_V1 {
        return Err(format!(
            "unsupported pseudonymize.norm `{norm}` (supported: {NORM_V1})"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validators_reject_unknown_norm_and_bad_widths() {
        assert!(validate_norm(NORM_V1).is_ok());
        assert!(validate_norm("v2").unwrap_err().contains("v2"));
        assert!(validate_token_bits(64).is_ok());
        assert!(validate_token_bits(72).is_ok());
        assert!(validate_token_bits(70).is_err());
        assert!(validate_token_bits(136).is_err());
    }
}
