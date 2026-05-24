# Configuration

`shk` reads project policy from `shk.toml` in the current working directory. If the file is absent, read-only commands use built-in defaults. Commands that write project or tool configuration require `shk.toml`.

Create a starter policy:

```bash
shk init
```

Create a stricter starter policy:

```bash
shk init --strict
```

## Policy Reference

Default policy shape, plus an optional `secrets push` profile example:

```toml
[scan]
include = ["**/*"]
exclude = [
  ".git/**",
  "node_modules/**",
  "dist/**",
  "build/**",
  "coverage/**",
  "**/*.svg",
  "**/*.png",
  "**/*.jpg",
  "**/*.jpeg",
  "**/*.gif",
  "**/*.webp",
  "**/*.ico",
  "**/*.icns",
  "**/*.avif",
  "**/*.bmp",
  "**/*.tif",
  "**/*.tiff",
  "**/*.mp4",
  "**/*.m4v",
  "**/*.mov",
  "**/*.webm",
  "**/*.mkv",
  "**/*.avi",
  "**/*.ogv",
  "**/*.mp3",
  "**/*.m4a",
  "**/*.wav",
  "**/*.flac",
  "**/*.aac",
  "**/*.ogg",
  "**/*.opus",
  "**/*.woff",
  "**/*.woff2",
  "**/*.ttf",
  "**/*.otf",
  "**/*.eot"
]
max_file_size_bytes = 1048576
binary_detection_bytes = 8192
follow_symlinks = false
include_binary = false

[rules]
secrets = true
pii = true
pii_languages = ["en", "ja"]
env = true
internal_terms = false
ai_context = true

[thresholds]
default_fail_on = "high"
scan_fail_on = "high"
pre_commit_fail_on = "high"

[mask]
mode = "strict"
min_severity = "medium"
redaction = "match"
# preserve_prefix = 4
# preserve_suffix = 4

[action_guard]
enabled = true
profile = "recommended"
allow = []
deny = []

[doctor.ignore]
required_patterns = [
  ".env",
  ".env.*",
  "!.env.example",
  "secrets/**",
  "credentials/**",
  "*.pem",
  "*.key",
  "*.p12",
  "*.mobileprovision",
  "*.log"
]

# Optional profiles for `shk secrets push`.
[secrets.profiles.prod]
provider = "aws"
mode = "blob"
target = "app/prod/dotenv"
source = ".env.production"
audit = true
confirm = true
```

`shk init --strict` uses the same structure but sets `default_fail_on`, `scan_fail_on`, and `pre_commit_fail_on` to `medium`.

## Scan Settings

| Key | Default | Behavior |
|-----|---------|----------|
| `include` | `["**/*"]` | Glob patterns included in scans. |
| `exclude` | Built-in generated file and media exclusions | Glob patterns excluded from scans. |
| `max_file_size_bytes` | `1048576` | Files larger than this limit are skipped. |
| `binary_detection_bytes` | `8192` | Number of leading bytes inspected for binary detection. |
| `follow_symlinks` | `false` | Whether scanner traversal follows symlinks. |
| `include_binary` | `false` | Whether binary-looking files are scanned instead of skipped. |

Supported document formats (`.docx`, `.xlsx`, `.pptx`, and text-layer `.pdf`) are text-extracted before binary skipping. Office findings are labelled with internal entry paths such as `report.docx:word/document.xml`; PDF findings use the PDF path itself. Image-only PDFs are not OCRed and produce `scan.document_text_empty` when no text can be extracted.

## Rule Settings

| Key | Default | Behavior |
|-----|---------|----------|
| `secrets` | `true` | Enables built-in secret rules. |
| `pii` | `true` | Enables built-in PII rules. |
| `pii_languages` | `["en", "ja"]` | Enables language-gated PII rules. Universal PII rules run when `pii = true`. |
| `env` | `true` | Enables env-related rules and hints. |
| `internal_terms` | `false` | Enables custom rules with `kind = "internal"`. |
| `ai_context` | `true` | Enables high-signal AI context safety rules for Unicode controls and unsafe URI schemes. |

## Thresholds

Valid severity values are `info`, `low`, `medium`, `high`, and `critical`.

| Key | Default | Behavior |
|-----|---------|----------|
| `default_fail_on` | `high` | Fallback threshold. |
| `scan_fail_on` | `high` | Threshold for normal scans. |
| `pre_commit_fail_on` | `high` | Threshold for `shk scan --staged` and Cursor pre-hook scans. |

The `--fail-on` CLI option overrides the configured threshold for that command invocation.

## Mask Settings

| Key | Default | Behavior |
|-----|---------|----------|
| `mode` | `strict` | Only `strict` is supported. Other values are rejected. |
| `min_severity` | `medium` | Minimum finding severity to redact. Use `info`, `low`, `medium`, `high`, or `critical`. |
| `redaction` | `match` | `match` redacts only matched values; `full` redacts entire lines; `partial` preserves configured matched-value edges. |
| `preserve_prefix` | `4` | Characters preserved at the start of a matched value when `redaction = "partial"`. |
| `preserve_suffix` | `4` | Characters preserved at the end of a matched value when `redaction = "partial"`. |

## Action Guard Settings

`action_guard` applies only to pre-hook scans such as `shk scan --hook-mode claude-code`. It checks operation intent before content scanning.

| Key | Default | Behavior |
|-----|---------|----------|
| `enabled` | `true` | Enables action guard blocking in pre-hook mode. |
| `profile` | `recommended` | Built-in coverage level: `minimal`, `recommended`, or `strict`. |
| `allow` | `[]` | Action patterns that bypass action guard, for project-approved operations. |
| `deny` | `[]` | Extra project-specific action patterns to block. |

Action patterns use tool-like strings with `*` wildcards, such as `Bash(psql:*)`, `Bash(kubectl delete:*)`, `Read(.env)`, or `Write(tokens/*.json)`. `allow` is checked before built-in and custom deny rules.

The `strict` profile also blocks opaque execution forms such as `bash -c`, `sh -c`, `python -c`, `node -e`, `ruby -e`, and `perl -e` instead of trying to fully interpret embedded scripts.

## Secret Manager Profiles

`[secrets.profiles.<name>]` stores reusable defaults for `shk secrets push`. CLI flags override profile values.

Blob mode stores the whole dotenv file as one provider secret:

```toml
[secrets.profiles.prod]
provider = "aws"
mode = "blob"
target = "app/prod/dotenv"
source = ".env.production"
region = "ap-northeast-1"
audit = true
confirm = true
create_if_missing = false
expected_env = "production"
```

Per-key mode stores each dotenv key under a target prefix:

```toml
[secrets.profiles.prod-keys]
provider = "gcp"
mode = "per-key"
target_prefix = "app/prod/"
source = ".env.keys"
project = "my-gcp-project"
location = "global"
audit = true
```

Supported profile keys:

| Key | Behavior |
|-----|----------|
| `provider` | `aws` or `gcp`. |
| `mode` | `blob` or `per-key`. Defaults to `blob` when omitted. |
| `target` | Blob mode target secret name. |
| `target_prefix` | Per-key mode target prefix. |
| `source` | Source dotenv file, resolved relative to the project root when relative. |
| `region` | AWS region. Otherwise AWS CLI environment/config is used. |
| `project` | GCP project. Otherwise gcloud environment/config is used. |
| `location` | GCP location. Defaults to `global`. |
| `audit` | Append metadata-only `.shk/audit.log` entries when `true`. |
| `confirm` | Prompt before writing when `true`. |
| `create_if_missing` | Create provider secrets when missing. |
| `expected_env` | Lint hint used for environment-like values such as `NODE_ENV`. |

Unknown profile fields are rejected. Raw secret values must not be placed in `shk.toml`; keep values in the source dotenv file or provider secret manager.

## Custom Rules

Add `[[custom_rules]]` entries for project-specific confidential words, codenames, or regex patterns:

```toml
[[custom_rules]]
id = "internal.codename"
pattern = "ProjectNebula|CONFIDENTIAL_CLIENT_X"
severity = "high"
kind = "internal"
message = "Internal confidential term detected"
case_insensitive = false
enabled = true
```

Fields:

| Field | Default | Behavior |
|-------|---------|----------|
| `id` | Required | Stable rule identifier. |
| `pattern` | Required | Rust regex pattern. |
| `severity` | `medium` | Finding severity. |
| `kind` | `internal` | Finding kind. |
| `message` | Generated from `id` | Finding message. |
| `confidence` | `1.0` | Finding confidence. |
| `case_insensitive` | `false` | Wraps the pattern in case-insensitive matching. |
| `enabled` | `true` | Enables or disables the rule. |

Custom rules participate in scan, mask, hook mode, inline suppression, and `[[allowlist]]`.

## Suppression

Inline suppression is available in files that support comments:

```text
API_KEY=synthetic-example-value  # shk-ignore secret.generic_api_key
# shk-ignore-next-line secret.generic_api_key
SECRET=synthetic-example-value
<!-- shk-ignore-next-line secret.generic_api_key -->
SECRET=synthetic-example-value
```

Policy allowlists can suppress by path and rule:

```toml
[[allowlist]]
rule_id = "secret.generic_api_key"
path = "fixtures/**"
reason = "Intentional test fixture"
expires = "2026-12-31"
```

For Office document findings, match the internal entry label shown in reports:

```toml
[[allowlist]]
rule_id = "secret.openai_api_key"
path = "report.docx:word/document.xml"
reason = "Intentional document fixture"
```

Policy allowlists can also suppress by value hash:

```toml
[[allowlist]]
rule_id = "pii.email"
value_hash = "sha256-hmac:a3f1..."
reason = "Public support address"
```

Do not place raw secret values in `shk.toml`. Use `value_hash` for value-specific suppression. A `value_hash` is a deterministic fingerprint for equality checks, not cryptographic secret storage; anyone who knows the candidate value and rule id can compute the same hash.

Expired allowlist entries produce low-severity warning findings.

## Doctor Ignore Settings

`doctor.ignore.required_patterns` controls the patterns checked by `shk doctor ignore`.

The default required patterns are:

```toml
[
  ".env",
  ".env.*",
  "!.env.example",
  "secrets/**",
  "credentials/**",
  "*.pem",
  "*.key",
  "*.p12",
  "*.mobileprovision",
  "*.log"
]
```

When `shk doctor ignore --fix` is used, missing required patterns are appended to `.gitignore`.
