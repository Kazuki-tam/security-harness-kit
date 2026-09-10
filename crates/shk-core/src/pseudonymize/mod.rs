//! Deterministic local-first pseudonymization (Phase 1a: CSV / TSV table mode).

mod columns;
mod derive;
mod kind;
mod normalize;
mod table;

pub use columns::{
    ColumnOverrides, ColumnPlan, ColumnSource, ResolvedColumn, infer_header, parse_columns_spec,
    resolve_columns,
};
pub use derive::{KeyMaterial, fingerprint, parse_stored_material, token};
pub use kind::{Kind, ParseKindError};
pub use normalize::{NormalizeOutcome, NormalizeSettings, normalize_value};
pub use table::{
    PseudonymizeJson, PseudonymizeMeta, TableOptions, TableResult, delimiter_for_path, run_table,
};

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
