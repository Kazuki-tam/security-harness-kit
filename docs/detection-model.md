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

## Finding Kinds

The rule engine supports these kinds:

| Kind | Usage |
|------|-------|
| `secret` | API keys, tokens, database URLs, private keys, and similar sensitive credentials. |
| `pii` | Personal information patterns. |
| `env` | Env-related rules and hints. |
| `ai-context` | AI-context-oriented rules. |
| `ignore` | Scanner skip notices and policy warnings. |
| `git` | Git-related findings. |

Not every kind is used by every command or built-in rule set.

## Built-In Secret Coverage

The built-in secret rules include patterns for:

- OpenAI-style API keys.
- AWS access key IDs.
- Anthropic API keys.
- Google API keys.
- GitHub tokens.
- Slack tokens.
- Stripe API keys.
- Database URLs with credentials.
- JWTs.
- Bearer tokens.
- Generic API key or secret key assignments.
- Private key PEM block headers.

These are pattern-based detections. Review findings before treating them as confirmed credentials.

## Hook Action Guard

In pre-hook mode, `shk scan --hook-mode <tool>` checks the AI tool payload for dangerous actions before scanning text content. This guard is separate from secret and PII detection: it looks at operation intent such as file paths and shell commands.

The initial guard blocks sensitive file reads/writes, `.env` dump commands, destructive recursive removal, direct database mutation commands, privilege or system changes, external transfer commands, and package manager operations. Projects can tune it with `[action_guard]` in `shk.toml`, including `profile`, `allow`, and `deny` patterns. In `strict` profile, opaque execution such as `bash -c`, `python -c`, and `node -e` is blocked rather than deeply interpreted. Audit mode still records findings without blocking.

## PII Coverage

Universal PII rules run when `pii = true`:

- Email addresses.
- Luhn-validated credit card numbers.
- IPv4 addresses.
- IPv6 addresses.

English PII rules run when `pii = true` and `pii_languages` includes `en`:

- Phone numbers.
- US Social Security Numbers.
- Label-anchored ZIP or postal codes.
- EINs.
- Passport numbers.
- Label-anchored street addresses.
- Label-anchored personal names.

Japanese PII rules run when `pii = true` and `pii_languages` includes `ja`:

- Phone numbers.
- Label-anchored or postal-mark-prefixed postal codes.
- Passport numbers.
- Label-anchored My Number values.
- Corporate numbers.
- Driver license numbers.
- Bank account patterns.
- Health insurance card patterns.
- Label-anchored personal names.

Personal names and English street addresses are label-anchored to reduce false positives.

## Binary And Large Files

By default, scanner traversal skips files larger than `scan.max_file_size_bytes` and binary-looking files. Binary detection checks the first `scan.binary_detection_bytes` bytes for NUL bytes.

In human output, informational skip findings are hidden unless `--verbose` is used. In JSON output, skip findings are included.

Use `--include-binary` or `scan.include_binary = true` to opt into scanning binary-looking files.

## JSON Output

```bash
shk scan . --json
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
  "color_mode": "never"
}
```

JSON scans include redacted surrounding context when context lines are available. Empty context fields are omitted from the serialized report.

## Masking Model

`shk mask` scans input and redacts matching lines or values according to policy:

- `redaction = "full"` replaces each line with at least one finding with `[REDACTED_LINE]`.
- `redaction = "partial"` replaces matched values with a `[REDACTED]` marker while preserving `preserve_prefix` and `preserve_suffix` characters.

Binary or non-UTF-8 input is not scanned by `shk mask`. Human output passes it through unchanged; JSON output reports `mask.binary_passthrough` and uses `[BINARY_PASSTHROUGH]` as masked content.

## Audit Log

`shk scan --hook-mode <tool> --audit` writes JSON lines to `.shk/audit.log`. Audit entries contain metadata such as tool name, hook phase, display path, finding count, suppressed count, and maximum severity. They do not contain raw matched values.
