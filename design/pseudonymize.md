# Pseudonymize (Phase 1b)

Internal contract for `shk mask --pseudonymize` and `shk pseudonymize`.
Public docs live in `docs/commands.md`. This file is out of the public
wording check.

## Status

Draft v0.4 is implemented through Phase 1b:

- CSV / TSV / xlsx table mode (`email`, `phone`, `name`, `custom`)
- Text mode (stdin, `.txt`, `.md`, `.docx`, `.pptx`, `--mode text`)
- HMAC-SHA256 tokens, HKDF per kind, stored salt (not `project_id`)
- Encrypted restore maps (`.shk-map`, ChaCha20-Poly1305)
- `--check-remaining` leftover scan (exit 1; not a sufficiency guarantee)
- Key show / rotate / delete / export `--instructions` / import `--stdin`
- `--output` required (except `--dry-run`)
- Dedicated `--json` metadata schema (no `masked_content`)

Out of scope: clipboard, hook-mode, `--delimiter`, delimiter-less JP phone
in text, libphonenumber, PDF rewrite.

## Stable contracts (do not change after 0.7)

- `norm = "v1"`
- HKDF info: `shk/pseudonymize/v1/<kind>` (`custom:<label>` for custom)
- Map HKDF info: `shk/pseudonymize/v1/map`
- Token: `<prefix>_<base32>` of the first `token_bits/8` HMAC bytes
- Stored material: `v1:<64 hex master>:<64 hex salt>`
- Fingerprint: SHA-256(master ‖ salt), first 8 bytes, lowercase hex
- Secret-store service: `security-harness-kit/pseudonymize`
- Map file: `SHKMAP ‖ version=1 ‖ nonce12 ‖ ciphertext` (no plaintext write path)

## Phase 1b notes

- xlsx table mode converts replaced cells to `inlineStr` so shared strings
  used by other cells are not rewritten.
- Office text mode concatenates each paragraph / shared-string group, runs
  the text engine, and splits the result back over the original runs by
  character count (the last run absorbs any growth), so run formatting
  survives; a token may therefore straddle two runs, which restore handles
  because it re-joins the group before matching.
- Text mode does not apply severity or allowlists.
- Restoring a token with multiple originals uses the first-seen value.
- Existing `--map` files must match the current key fingerprint or the
  command exits 2.
- `pii.shk_plaintext_map` (High) flags a line holding a whole built-in token
  (`\b(?:email|phone|name)_[a-z2-7]{13,26}\b`) plus a real email or a
  delimited phone. It is word-bounded so identifiers such as
  `email_template_id` never match, and `--check-remaining` ignores it because
  every pseudonymized output contains tokens. Custom labels are not covered.
- Text-mode name rules match with their label; the label is kept and only
  the name is tokenized (`split_name_label`).
- xlsx parsing ignores `<rPh>` phonetic runs, positions `<row>`/`<c>` without
  `r` after their predecessor (`CellCursor`), treats `<c t="s"><v/></c>` as
  empty, and skips blank rows above the table before header inference.
- Unknown XML entities (`&nbsp;`) and control-character references (`&#xD;`)
  are passed through untouched by the Office rewrite; predefined entities and
  printable character references are merged into the surrounding text.
- `--columns` entries that match no header are an error (typo guard);
  `[pseudonymize.columns]` entries are project-wide and may not apply.
- `[pseudonymize.columns]` / `[pseudonymize.rules]` kinds are validated
  before any prompt or key creation.
- Text-mode metadata lists kinds with `source = "rule"`.
- Per-kind HKDF keys are cached inside `KeyMaterial` (zeroized on drop) so a
  table costs one HMAC per cell; `TokenIndex` is built once per restore and
  matches longest-token-first, replacing only complete known tokens.
- Mutating operations use a project-scoped process lock. Restore maps are
  limited to 64 MiB; map and metadata artifacts are committed before output.
- Key import refuses to replace existing material.
- Exit codes: `--check-remaining` leftovers exit 1; every other failure on
  the pseudonymize path exits 2 (`fail_run` preserves explicit `CliExit`s).
