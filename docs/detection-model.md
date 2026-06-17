# Detection Model

`shk` scans text with built-in regex-based rules and optional project custom rules. Findings include a rule id, severity, kind, file label, line, column, message, redacted value, and confidence score.

Raw matched values are not emitted in JSON reports. `redacted_value` is `[REDACTED]`.

## Severity Levels

| Level | Examples |
|-------|----------|
| `critical` | Private key PEM blocks. |
| `high` | OpenAI-style keys, AWS access key IDs, Anthropic keys, Google API keys, GitHub tokens, Slack tokens, Stripe keys, database URLs. |
| `medium` | JWTs, bearer tokens, generic API key assignments, email, credit card numbers, most English/Japanese PII rules. |
| `low` | IP addresses and policy warnings such as expired allowlist entries. |
| `info` | Skip notices and informational findings. |

## AI Context Safety Coverage

AI-context rules run when `ai_context = true` in `[rules]` and report findings with kind `ai-context`.

The default rule set focuses on high-signal syntax that can alter or obscure AI-visible context:

- `ai_context.unicode_tag_chars` (`high`): Unicode tag characters (`U+E0000..U+E007F`).
- `ai_context.bidi_control` (`high` in source-code files, `low` in other text): bidirectional control characters associated with Trojan Source-style visual reordering.
- `ai_context.embedded_bom` (`medium`): byte order marks after the start of a file.
- `ai_context.invisible_format_chars` (`high`): invisible Unicode format characters such as soft hyphen, combining grapheme joiner, Arabic letter mark, Mongolian vowel separator, zero-width space, and word joiner. Zero-width joiner/non-joiner are excluded by default to avoid common emoji and script-shaping false positives.
- `ai_context.variation_selector` (`medium`): Supplemental Unicode variation selectors (`U+E0100..U+E01EF`) that can alter visual presentation. Common emoji presentation selectors (`U+FE00..U+FE0F`) are excluded by default.
- `ai_context.unsafe_uri` (`high`, or `medium` for SVG data URIs): JavaScript-scheme links and executable `data` URI media types such as `text/html`, `text/javascript`, `image/svg+xml`, and JavaScript application types.

Lower-confidence detectors such as Markdown image exfiltration and natural-language prompt-injection phrases are not part of the default rule set.

## Finding Kinds

The rule engine supports these kinds:

| Kind | Usage |
|------|-------|
| `secret` | API keys, tokens, database URLs, private keys, and similar sensitive credentials. |
| `pii` | Personal information patterns. |
| `env` | Env-related rules and hints. The built-in `env.sensitive_assignment` rule flags dotenv-style assignments of sensitive variable names (`*PASSWORD*`, `*SECRET*`, `*TOKEN*`, `*API_KEY*`, `*PRIVATE_KEY*`, `*ACCESS_KEY*`, `*CREDENTIAL*`) with non-placeholder values. Env rules only apply to dotenv-style files (file name starting with `.env` or ending in `.env`), so source code reading the environment (e.g. `DB_PASSWORD = os.environ[...]`) is not flagged. `.env.example` and `.env.sample` files are skipped, and `[rules] env = false` disables the kind. |
| `ai-context` | AI-context-oriented rules. |
| `ignore` | Scanner skip notices and policy warnings. |
| `git` | Git-related findings. |

Not every kind is used by every command or built-in rule set.

## Built-In Secret Coverage

The built-in secret rules combine two sources:

- Hand-tuned `shk` rules in `crates/shk-rules/src/lib.rs`.
- Generated `secret.gitleaks.*` rules adapted from the gitleaks default configuration in `crates/shk-rules/src/gitleaks_rules.rs`.

The hand-tuned `shk` rules include patterns for:

- OpenAI-style API keys.
- AWS access key IDs.
- Anthropic API keys.
- Google API keys.
- GitHub tokens.
- Slack tokens.
- Stripe API keys.
- Hugging Face tokens.
- Label-anchored Twilio auth tokens.
- SendGrid API keys.
- Shopify tokens.
- Supabase service role keys.
- Label-anchored Vercel tokens.
- npm tokens.
- GitLab personal access tokens.
- Discord webhook URLs.
- Label-anchored Cloudflare API tokens.
- Label-anchored Notion integration tokens.
- Linear API keys.
- Database URLs with credentials.
- JWTs.
- Bearer tokens.
- Generic API key or secret key assignments.
- Private key PEM block headers.

The generated gitleaks-derived rules add broader service coverage for provider-specific API keys, access tokens, client secrets, webhook URLs, cloud credentials, package registry tokens, and related secret formats. They preserve key gitleaks rule semantics where practical, including keyword prefilters, path-limited rules, `secretGroup` extraction for the reported secret value, entropy thresholds, and rule-level allowlists.

Generated gitleaks rule ids use the `secret.gitleaks.<upstream-id>` namespace so they do not collide with existing `shk` rule ids. A small number of upstream rules are intentionally skipped when they are path-only, overlap with existing tuned `shk` rules, or exceed Rust `regex` compiled-size limits. See `THIRD_PARTY_LICENSES.md` for the gitleaks license and source commit.

These are pattern-based detections. Review findings before treating them as confirmed credentials.

## Hook Action Guard

In pre-hook mode, `shk scan --hook-mode <tool>` checks the AI tool payload for dangerous actions before scanning text content. This guard is separate from secret and PII detection: it looks at operation intent such as file paths and shell commands.

The initial guard blocks sensitive file reads/writes, `.env` dump commands, environment dump commands such as `printenv`, `env`, `export -p`, `set | ...`, shell `-c` environment dumps, and common interpreter environment reads such as Python `os.environ`, Node `process.env`, Ruby `ENV`, and Perl `%ENV`, destructive recursive removal, direct database mutation commands, privilege or system changes, external transfer commands, and package manager operations. Projects can tune it with `[action_guard]` in `shk.toml`, including `profile`, `allow`, and `deny` patterns. In `strict` profile, opaque execution such as `bash -c`, `python -c`, and `node -e` is blocked rather than deeply interpreted. Audit mode still records findings without blocking.

## PII Coverage

Universal PII rules run when `pii = true`:

- Email addresses.
- Luhn-validated credit card numbers.
- IPv4 addresses.
- IPv6 addresses.

English PII rules run when `pii = true` and `pii_languages` includes `en`:

- Phone numbers.
- Label-anchored US Social Security Numbers.
- Label-anchored ZIP or postal codes.
- EINs.
- Passport numbers.
- Label-anchored street addresses.
- Label-anchored personal names.

Japanese PII rules run when `pii = true` and `pii_languages` includes `ja`:

- Phone numbers.
- Label-anchored or postal-mark-prefixed postal codes.
- Label-anchored passport numbers.
- Label-anchored My Number values.
- Corporate numbers.
- Driver license numbers.
- Bank account patterns.
- Health insurance card patterns.
- Label-anchored personal names.

Personal names, English street addresses, English SSNs, and Japanese passport numbers are label-anchored to reduce false positives.

## Binary And Large Files

By default, scanner traversal skips files larger than `scan.max_file_size_bytes` and binary-looking files. Binary detection checks the first `scan.binary_detection_bytes` bytes for NUL bytes.

In human-readable output, informational skip findings are hidden unless `--verbose` is used. In JSON output, skip findings are included.

Use `--include-binary` or `scan.include_binary = true` to opt into scanning binary-looking files.

## Document Text Extraction

Before binary skipping, `shk scan` attempts text extraction for supported document formats:

- `.docx`: scans `word/document.xml`.
- `.xlsx`: scans shared strings and worksheet inline strings.
- `.pptx`: scans slide, notes slide, and comment text.
- `.pdf`: scans the embedded text layer.

Office findings use internal entry labels such as `report.docx:word/document.xml` or `workbook.xlsx:xl/sharedStrings.xml`. PDF findings use the PDF file path itself. Path-based allowlists should match those labels.

The extractor handles common Office rich-text splits by joining text within logical document text groups before scanning. PDF support does not perform OCR; image-only PDFs report `scan.document_text_empty` when no text can be extracted.

## JSON Output

```bash
shk scan . --json
shk scan . --json --with-value-hash
```

Example report:

```json
{
  "version": 1,
  "scanned_paths": ["src/app.ts"],
  "findings": [
    {
      "rule_id": "secret.openai_api_key",
      "severity": "high",
      "kind": "secret",
      "file": "src/app.ts",
      "line": 12,
      "column": 18,
      "message": "Possible OpenAI API key detected",
      "redacted_value": "[REDACTED]",
      "confidence": 0.9
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": {
      "high": 1
    }
  },
  "exit_threshold": "high",
  "suppressed": 0,
  "deduplicated": 0,
  "color_mode": "never"
}
```

JSON scans include redacted surrounding context when context lines are available. Empty context fields are omitted from the serialized report. Repeated findings with the same rule and value in a single scanned file are emitted once and counted in `deduplicated`.

When `--with-value-hash` is passed, each content finding also includes `value_hash`, which is `HMAC-SHA256(raw_value, rule_id)` formatted as `sha256-hmac:<hex>`. It supports value-specific `[[allowlist]]` entries and `shk allowlist suggest --value-hash` without printing raw matched values.

Value hashes are deterministic and keyed by public rule IDs. They are not raw values, but low-entropy values such as common email addresses, names, or phone numbers may be recoverable by dictionary attack. Treat reports containing value hashes as sensitive artifacts, especially when exporting SARIF or CI logs to third-party systems.

## Masking Model

`shk mask` scans input and redacts matching lines or values according to policy:

- `min_severity = "medium"` redacts findings at `medium`, `high`, and `critical` by default; use `--min-severity` or `[mask].min_severity` to lower or raise the mask threshold.
- `redaction = "match"` replaces only matched values with `[REDACTED]`.
- `redaction = "full"` replaces each line with at least one finding with `[REDACTED_LINE]`.
- `redaction = "partial"` replaces matched values with a `[REDACTED]` marker while preserving `preserve_prefix` and `preserve_suffix` characters.

Binary or non-UTF-8 input is not scanned by `shk mask`. Human output passes it through unchanged; JSON output reports `mask.binary_passthrough` and uses `[BINARY_PASSTHROUGH]` as masked content.

Office document masking supports `.docx`, `.xlsx`, and `.pptx` with `--output`; it writes a new document and leaves the original unchanged. PDF masking is not supported.

## Audit Log

`shk scan --hook-mode <tool> --audit` writes JSON lines to `.shk/audit.log`. Audit entries contain metadata such as tool name, hook phase, display path, finding count, suppressed count, deduplicated count, and maximum severity. They do not contain raw matched values.

`shk scan --hook-mode <tool> --log-blocked` keeps pre-hook blocking behavior and writes metadata-only `event = "blocked"` entries for blocked pre-hook and user-prompt events. With `--post`, it stays non-blocking and writes `event = "audit"` entries for post-hook scans. Finding-threshold block entries include rule IDs, finding kinds, counts, and maximum severity for findings at or above the active threshold. Action guard block entries include only the action category, not the command text, file path, prompt body, or guard reason.

Use `shk audit` to preview `.shk/audit.log`:

```bash
shk audit
shk audit --reason finding-threshold
shk audit --reason action-guard --no-paths
shk audit --since 7d --tool cursor --json
```

`shk secrets push --audit` also writes metadata-only JSON lines to `.shk/audit.log`. Secret push audit entries include fields such as provider, mode, source label, byte count, payload SHA-256 hash, target label, key counts, operation, and status. They do not contain raw dotenv values or per-key secret payloads.
