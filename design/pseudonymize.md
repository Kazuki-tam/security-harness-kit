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
  the text engine, and writes the (possibly longer) result to the first
  text node.
- Text mode does not apply severity or allowlists.
- Restoring a token with multiple originals uses the first-seen value.
- Existing `--map` files must match the current key fingerprint or the
  command exits 2.
- `pii.shk_plaintext_map` flags a line that contains both a token prefix
  and an email/phone-like original.
