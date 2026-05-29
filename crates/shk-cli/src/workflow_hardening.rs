//! GitHub Actions workflow hardening checks.
//!
//! Detects `actions/checkout` steps that do not set `persist-credentials: false`.
//! Leaving credential persistence enabled keeps a Git credential file
//! (`$RUNNER_TEMP/git-credentials-*.config`) on disk for later steps, so a
//! compromised or injected later step can read the workflow's GitHub token.
//!
//! The scanner is intentionally line-oriented rather than a full YAML parse so
//! that `--fix` can insert the missing key while preserving the file's existing
//! formatting and comments.

use std::fs;
use std::path::{Path, PathBuf};

/// Relative directory (from the project root) that holds workflow files.
const WORKFLOWS_DIR: &str = ".github/workflows";

/// State of `persist-credentials` for a single `actions/checkout` step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistState {
    /// `persist-credentials` is absent from the step.
    Missing,
    /// `persist-credentials: true` is set explicitly.
    ExplicitTrue,
    /// `persist-credentials: false` is set (the hardened state).
    Disabled,
}

/// One `actions/checkout` step found in a workflow file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CheckoutStep {
    /// 1-based line number of the `uses: actions/checkout` line.
    pub line: usize,
    pub state: PersistState,
}

impl CheckoutStep {
    pub fn needs_fix(&self) -> bool {
        !matches!(self.state, PersistState::Disabled)
    }
}

/// Result of scanning a single workflow file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkflowFileStatus {
    /// Path relative to the project root, using forward slashes.
    pub relative_path: String,
    pub checkout_steps: Vec<CheckoutStep>,
}

impl WorkflowFileStatus {
    pub fn findings(&self) -> impl Iterator<Item = &CheckoutStep> {
        self.checkout_steps.iter().filter(|s| s.needs_fix())
    }

    pub fn ok(&self) -> bool {
        self.checkout_steps.iter().all(|s| !s.needs_fix())
    }
}

/// Outcome of `--fix` applied to a single file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkflowFixResult {
    pub relative_path: String,
    pub fixed_steps: usize,
}

/// Scan all workflow files under `<root>/.github/workflows`.
///
/// Returns one entry per workflow file that contains at least one
/// `actions/checkout` step, sorted by relative path for stable output.
pub fn scan_workflows(root: &Path) -> Vec<WorkflowFileStatus> {
    let mut statuses = Vec::new();
    for path in workflow_files(root) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let steps = analyze(&content);
        if steps.is_empty() {
            continue;
        }
        let relative_path = relative_label(root, &path);
        statuses.push(WorkflowFileStatus {
            relative_path,
            checkout_steps: steps,
        });
    }
    statuses.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    statuses
}

/// Apply `persist-credentials: false` hardening to one workflow file in place.
pub fn fix_file(path: &Path) -> std::io::Result<usize> {
    let content = fs::read_to_string(path)?;
    let (fixed, count) = fix_content(&content);
    if count > 0 {
        fs::write(path, fixed)?;
    }
    Ok(count)
}

/// Harden every flagged workflow file under `root`, enforcing the workspace
/// write-safety policy (`safety::ensure_writable_path_allowed`) before each
/// write. Returns one entry per file that changed.
///
/// This is the single place that mutates workflow files, so callers (CLI and
/// desktop) share identical safety behaviour. Callers remain responsible for
/// any higher-level preconditions such as `safety::require_project_policy` or
/// desktop project-root allow-listing.
pub fn fix_all(root: &Path) -> anyhow::Result<Vec<WorkflowFixResult>> {
    let mut fixes = Vec::new();
    for status in scan_workflows(root) {
        if status.ok() {
            continue;
        }
        let file_path = root.join(&status.relative_path);
        crate::safety::ensure_writable_path_allowed(&file_path)?;
        let fixed_steps = fix_file(&file_path)?;
        if fixed_steps > 0 {
            fixes.push(WorkflowFixResult {
                relative_path: status.relative_path,
                fixed_steps,
            });
        }
    }
    Ok(fixes)
}

fn workflow_files(root: &Path) -> Vec<PathBuf> {
    let dir = root.join(WORKFLOWS_DIR);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && is_yaml(p))
        .collect();
    files.sort();
    files
}

fn is_yaml(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yml") | Some("yaml")
    )
}

fn relative_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn leading_spaces(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

fn is_blank_or_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.is_empty() || trimmed.starts_with('#')
}

/// Indentation of a YAML block-sequence item (`- ...`), if the line is one.
fn list_item_indent(line: &str) -> Option<usize> {
    let indent = leading_spaces(line);
    let rest = &line[indent..];
    if rest == "-" || rest.starts_with("- ") {
        Some(indent)
    } else {
        None
    }
}

/// Returns the boundary (exclusive end index) of the step block beginning at `start`.
fn step_block_end(lines: &[&str], start: usize) -> usize {
    let dash_indent = leading_spaces(lines[start]);
    let mut end = start + 1;
    while end < lines.len() {
        let line = lines[end];
        if is_blank_or_comment(line) {
            end += 1;
            continue;
        }
        if leading_spaces(line) <= dash_indent {
            break;
        }
        end += 1;
    }
    end
}

/// Strip a leading block-sequence dash (`- `) so we can inspect the step's
/// mapping key (e.g. `uses:` / `with:`) regardless of whether it sits on the
/// dash line or a continuation line.
fn step_key_part(line: &str) -> &str {
    let trimmed = line.trim_start();
    trimmed.strip_prefix("- ").unwrap_or(trimmed)
}

/// Drop a trailing `# ...` comment. The workflow scalars we inspect (`uses:`
/// values, `persist-credentials:` values) never contain a literal `#`, so a
/// plain split is sufficient.
fn strip_inline_comment(value: &str) -> &str {
    value.split('#').next().unwrap_or(value)
}

fn is_checkout_uses(line: &str) -> bool {
    let Some(value) = step_key_part(line).strip_prefix("uses:") else {
        return false;
    };
    let value = strip_inline_comment(value).trim().trim_matches(['"', '\'']);
    value == "actions/checkout" || value.starts_with("actions/checkout@")
}

fn is_with_key(line: &str) -> bool {
    step_key_part(line).starts_with("with:")
}

fn persist_state(line: &str) -> Option<PersistState> {
    let value = line.trim_start().strip_prefix("persist-credentials:")?;
    let value = strip_inline_comment(value).trim().trim_matches(['"', '\'']);
    if value == "false" {
        Some(PersistState::Disabled)
    } else {
        Some(PersistState::ExplicitTrue)
    }
}

fn disabled_persist_credentials_line(line: &str) -> String {
    let indent = leading_spaces(line);
    let replacement = format!("{}persist-credentials: false", &line[..indent]);
    let Some(comment_start) = line.find('#') else {
        return replacement;
    };

    let before_comment = &line[..comment_start];
    let spacing_start = before_comment.trim_end_matches(char::is_whitespace).len();
    let spacing = &before_comment[spacing_start..];
    format!("{replacement}{spacing}{}", &line[comment_start..])
}

/// Half-open `[start, end)` line ranges for each top-level step in a block
/// sequence (`- ...` items), including each step's indented continuation lines.
fn step_ranges(lines: &[&str]) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if list_item_indent(lines[i]).is_some() {
            let end = step_block_end(lines, i);
            ranges.push(i..end);
            i = end;
        } else {
            i += 1;
        }
    }
    ranges
}

/// Identify every `actions/checkout` step in a workflow and its persist state.
fn analyze(content: &str) -> Vec<CheckoutStep> {
    let lines: Vec<&str> = content.lines().collect();
    step_ranges(&lines)
        .into_iter()
        .filter_map(|range| {
            let block = &lines[range.clone()];
            let uses_offset = block.iter().position(|l| is_checkout_uses(l))?;
            let state = block
                .iter()
                .find_map(|l| persist_state(l))
                .unwrap_or(PersistState::Missing);
            Some(CheckoutStep {
                line: range.start + uses_offset + 1,
                state,
            })
        })
        .collect()
}

fn preferred_line_ending(content: &str) -> &'static str {
    if content.as_bytes().windows(2).any(|w| w == b"\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

/// Rewrite the workflow content so each `actions/checkout` step sets
/// `persist-credentials: false`. Returns the new content and the number of
/// steps that were changed.
fn fix_content(content: &str) -> (String, usize) {
    let line_ending = preferred_line_ending(content);
    let lines: Vec<&str> = content.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 4);
    let mut fixed = 0;
    let mut i = 0;

    while i < lines.len() {
        let Some(dash_indent) = list_item_indent(lines[i]) else {
            out.push(lines[i].to_string());
            i += 1;
            continue;
        };
        let end = step_block_end(&lines, i);
        let (rendered, changed) = harden_checkout_step(&lines[i..end], dash_indent);
        out.extend(rendered);
        if changed {
            fixed += 1;
        }
        i = end;
    }

    let mut result = out.join(line_ending);
    if content.ends_with('\n') {
        result.push_str(line_ending);
    }
    (result, fixed)
}

/// Render a single step block, inserting `persist-credentials: false` when the
/// step is an `actions/checkout` that does not already disable persistence.
/// Returns the rendered lines and whether a change was made.
fn harden_checkout_step(block: &[&str], dash_indent: usize) -> (Vec<String>, bool) {
    let owned = || block.iter().map(|l| l.to_string()).collect::<Vec<_>>();

    let already_hardened = block
        .iter()
        .any(|l| persist_state(l) == Some(PersistState::Disabled));
    if !block.iter().any(|l| is_checkout_uses(l)) || already_hardened {
        return (owned(), false);
    }

    // Explicit non-`false` value: flip it in place, preserving indentation.
    if let Some(offset) = block
        .iter()
        .position(|l| persist_state(l) == Some(PersistState::ExplicitTrue))
    {
        let mut lines = owned();
        lines[offset] = disabled_persist_credentials_line(block[offset]);
        return (lines, true);
    }

    // Missing entirely: add it under an existing `with:` block, or create one.
    let mut lines: Vec<String> = Vec::with_capacity(block.len() + 2);
    if let Some(w) = block.iter().position(|l| is_with_key(l)) {
        let with_indent = leading_spaces(block[w]);
        let child_indent = block
            .get(w + 1)
            .filter(|l| !is_blank_or_comment(l) && leading_spaces(l) > with_indent)
            .map(|l| leading_spaces(l))
            .unwrap_or(with_indent + 2);
        for (idx, line) in block.iter().enumerate() {
            lines.push((*line).to_string());
            if idx == w {
                lines.push(format!(
                    "{}persist-credentials: false",
                    " ".repeat(child_indent)
                ));
            }
        }
    } else {
        let uses_offset = block.iter().position(|l| is_checkout_uses(l)).unwrap_or(0);
        let key_indent = dash_indent + 2;
        for (idx, line) in block.iter().enumerate() {
            lines.push((*line).to_string());
            if idx == uses_offset {
                lines.push(format!("{}with:", " ".repeat(key_indent)));
                lines.push(format!(
                    "{}persist-credentials: false",
                    " ".repeat(key_indent + 2)
                ));
            }
        }
    }
    (lines, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_missing_persist_credentials() {
        let yaml = "\
jobs:
  build:
    steps:
      - uses: actions/checkout@v6
      - name: build
        run: echo hi
";
        let steps = analyze(yaml);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].state, PersistState::Missing);
        assert_eq!(steps[0].line, 4);
    }

    #[test]
    fn detects_disabled_persist_credentials() {
        let yaml = "\
jobs:
  build:
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
";
        let steps = analyze(yaml);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].state, PersistState::Disabled);
    }

    #[test]
    fn detects_explicit_true_persist_credentials() {
        let yaml = "\
jobs:
  build:
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: true
          fetch-depth: 0
";
        let steps = analyze(yaml);
        assert_eq!(steps[0].state, PersistState::ExplicitTrue);
    }

    #[test]
    fn detects_named_step_checkout() {
        let yaml = "\
jobs:
  build:
    steps:
      - name: checkout
        uses: actions/checkout@v6
";
        let steps = analyze(yaml);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].state, PersistState::Missing);
        assert_eq!(steps[0].line, 5);
    }

    #[test]
    fn detects_checkout_with_inline_comment_and_quotes() {
        let yaml = "\
jobs:
  build:
    steps:
      - uses: \"actions/checkout@v6\" # pinned
      - uses: actions/checkout # bare
";
        let steps = analyze(yaml);
        assert_eq!(steps.len(), 2);
        assert!(steps.iter().all(|s| s.state == PersistState::Missing));
    }

    #[test]
    fn ignores_non_checkout_steps() {
        let yaml = "\
jobs:
  build:
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 22
";
        assert!(analyze(yaml).is_empty());
    }

    #[test]
    fn fix_adds_with_block_when_missing() {
        let yaml = "\
jobs:
  build:
    steps:
      - uses: actions/checkout@v6

      - name: build
        run: echo hi
";
        let (fixed, count) = fix_content(yaml);
        assert_eq!(count, 1);
        assert!(
            fixed.contains("      - uses: actions/checkout@v6\n        with:\n          persist-credentials: false\n"),
            "{fixed}"
        );
        // Re-running is idempotent.
        assert_eq!(fix_content(&fixed).1, 0);
        assert!(analyze(&fixed).iter().all(|s| !s.needs_fix()));
    }

    #[test]
    fn fix_preserves_crlf_line_endings() {
        let yaml = "jobs:\r\n  build:\r\n    steps:\r\n      - uses: actions/checkout@v6\r\n      - name: build\r\n        run: echo hi\r\n";

        let (fixed, count) = fix_content(yaml);

        assert_eq!(count, 1);
        assert!(
            fixed.contains(
                "      - uses: actions/checkout@v6\r\n        with:\r\n          persist-credentials: false\r\n"
            ),
            "{fixed:?}"
        );
        assert!(!fixed.contains("checkout@v6\n        with:"), "{fixed:?}");
        assert!(fixed.ends_with("\r\n"), "{fixed:?}");
    }

    #[test]
    fn fix_appends_to_existing_with_block() {
        let yaml = "\
jobs:
  build:
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
";
        let (fixed, count) = fix_content(yaml);
        assert_eq!(count, 1);
        assert!(
            fixed.contains(
                "        with:\n          persist-credentials: false\n          fetch-depth: 0"
            ),
            "{fixed}"
        );
        assert_eq!(fix_content(&fixed).1, 0);
    }

    #[test]
    fn fix_flips_explicit_true() {
        let yaml = "\
jobs:
  build:
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: true
";
        let (fixed, count) = fix_content(yaml);
        assert_eq!(count, 1);
        assert!(fixed.contains("persist-credentials: false"), "{fixed}");
        assert!(!fixed.contains("persist-credentials: true"), "{fixed}");
    }

    #[test]
    fn fix_preserves_inline_comment_when_flipping_explicit_true() {
        let yaml = "\
jobs:
  build:
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: true  # needed before release automation was split
";
        let (fixed, count) = fix_content(yaml);
        assert_eq!(count, 1);
        assert!(
            fixed.contains(
                "          persist-credentials: false  # needed before release automation was split"
            ),
            "{fixed}"
        );
        assert!(!fixed.contains("persist-credentials: true"), "{fixed}");
    }

    #[test]
    fn fix_preserves_named_step_indentation() {
        let yaml = "\
jobs:
  build:
    steps:
      - name: checkout
        uses: actions/checkout@v6
      - name: build
        run: echo hi
";
        let (fixed, count) = fix_content(yaml);
        assert_eq!(count, 1);
        assert!(
            fixed.contains(
                "        uses: actions/checkout@v6\n        with:\n          persist-credentials: false\n"
            ),
            "{fixed}"
        );
    }

    #[test]
    fn fix_leaves_disabled_steps_untouched() {
        let yaml = "\
jobs:
  build:
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
";
        let (fixed, count) = fix_content(yaml);
        assert_eq!(count, 0);
        assert_eq!(fixed, yaml);
    }
}
