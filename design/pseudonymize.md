# Pseudonymize (Phase 1a / 0.7.0)

Internal contract for `shk mask --pseudonymize` and `shk pseudonymize key`.
Public docs live in `docs/commands.md`. This file is out of the public
wording check.

## Status

Draft v0.4 decisions are implemented for Phase 1a only:

- CSV / TSV table mode (`email`, `phone`, `custom`)
- HMAC-SHA256 tokens, HKDF per kind, stored salt (not `project_id`)
- Key show / rotate / delete / export `--instructions` / import `--stdin`
- `--output` required (except `--dry-run`)
- Dedicated `--json` metadata schema (no `masked_content`)

Phase 1b (0.8.0): xlsx, text mode, `name`, restore maps, `--check-remaining`.

## Stable contracts (do not change after 0.7)

- `norm = "v1"`
- HKDF info: `shk/pseudonymize/v1/<kind>` (`custom:<label>` for custom)
- Token: `<prefix>_<base32>` of the first `token_bits/8` HMAC bytes
- Stored material: `v1:<64 hex master>:<64 hex salt>`
- Fingerprint: SHA-256(master ‖ salt), first 8 bytes, lowercase hex
- Secret-store service: `security-harness-kit/pseudonymize`
