//! `shk clipboard scan` / `shk clipboard mask` — scan or mask OS clipboard text.
//!
//! Clipboard contents are treated like any other untrusted input: raw text is
//! zeroized after scanning/masking and never printed unmasked by `mask`.
//! Clipboard access failures (no display server, denied access, …) exit with
//! code 2 like other runtime/environment errors.

use crate::args::{RedactionMode, SeverityArg};
use crate::commands::mask::{apply_min_severity_override, apply_redaction_override};
use crate::exit::CliExit;
use crate::output;
use anyhow::{Context, Result};
use shk_core::finding::Finding;
use shk_core::masker::MaskJsonOutput;
use shk_core::policy::{ColorMode, Policy, Severity};
use shk_core::scanner::{ScanOptions, ScanResult, scan_string};
use std::path::Path;
use zeroize::Zeroize;

/// Display label used instead of a file path in findings and reports.
const CLIPBOARD_LABEL: &str = "<clipboard>";

#[derive(Clone, Debug)]
pub struct ClipboardScanInvocation {
    pub json: bool,
    pub verbose: bool,
    pub fail_on: Option<SeverityArg>,
    pub color_enabled: bool,
}

#[derive(Clone, Debug)]
pub struct ClipboardMaskInvocation {
    pub json: bool,
    pub write: bool,
    pub redaction: Option<RedactionMode>,
    pub min_severity: Option<SeverityArg>,
}

pub fn scan(inv: ClipboardScanInvocation) -> Result<()> {
    let cwd = std::env::current_dir().context("current directory for policy resolution")?;
    let mut text = read_clipboard_text()?;
    let res = scan_clipboard_output(&cwd, &text, &inv);
    text.zeroize();
    let output = res.context("clipboard scan failed")?;
    print!("{}", output.stdout);
    if output.should_fail {
        return Err(CliExit::silent(1).into());
    }
    Ok(())
}

pub fn mask(inv: ClipboardMaskInvocation) -> Result<()> {
    let cwd = std::env::current_dir().context("current directory for policy resolution")?;
    let mut text = read_clipboard_text()?;
    let mask_result = mask_clipboard_output(&cwd, &text, &inv);
    text.zeroize();
    let mut output = mask_result.context("clipboard mask failed")?;

    if inv.write {
        write_clipboard_text(&output.masked)?;
    }

    print!("{}", output.stdout);
    output.masked.zeroize();
    Ok(())
}

#[derive(Debug)]
struct ClipboardScanOutput {
    stdout: String,
    should_fail: bool,
}

#[derive(Debug)]
struct ClipboardMaskOutput {
    stdout: String,
    masked: String,
}

fn scan_clipboard_output(
    root: &Path,
    text: &str,
    inv: &ClipboardScanInvocation,
) -> Result<ClipboardScanOutput> {
    let res = scan_clipboard_text(root, text, inv.json, inv.fail_on)?;
    let stdout = if inv.json {
        format!(
            "{}\n",
            serde_json::to_string_pretty(&res.to_json_report(ColorMode::Never))?
        )
    } else {
        format!(
            "{}{}\n",
            output::format_human_findings(
                &res.findings,
                inv.color_enabled,
                inv.verbose,
                res.deduplicated,
            ),
            output::format_scan_summary(
                output::max_human_severity(&res.findings, inv.verbose),
                res.exit_threshold,
                inv.color_enabled,
            )
        )
    };
    Ok(ClipboardScanOutput {
        stdout,
        should_fail: res.should_fail(),
    })
}

fn mask_clipboard_output(
    root: &Path,
    text: &str,
    inv: &ClipboardMaskInvocation,
) -> Result<ClipboardMaskOutput> {
    let (masked, findings) = mask_clipboard_text(root, text, inv.redaction, inv.min_severity)?;
    let finding_count = findings.len();
    let stdout = if inv.json {
        let out = MaskJsonOutput {
            masked_content: masked.clone(),
            findings,
        };
        format!("{}\n", serde_json::to_string_pretty(&out)?)
    } else if inv.write {
        format!("Replaced clipboard with masked text ({finding_count} finding(s) redacted)\n")
    } else {
        masked.clone()
    };
    Ok(ClipboardMaskOutput { stdout, masked })
}

fn scan_clipboard_text(
    root: &Path,
    text: &str,
    json: bool,
    fail_on: Option<SeverityArg>,
) -> Result<ScanResult> {
    let opts = ScanOptions {
        staged: false,
        git_history: false,
        git_history_ref: None,
        git_history_since: None,
        git_history_max_commits: None,
        json,
        fail_on_override: fail_on.map(Severity::from),
        use_pre_commit_threshold: false,
        include_context: false,
        include_binary: false,
        follow_symlinks: false,
    };
    scan_string(root, CLIPBOARD_LABEL, text, opts)
}

fn mask_clipboard_text(
    root: &Path,
    text: &str,
    redaction: Option<RedactionMode>,
    min_severity: Option<SeverityArg>,
) -> Result<(String, Vec<Finding>)> {
    let (mut policy, _) = Policy::load_from_dir(root)?;
    apply_redaction_override(&mut policy, redaction);
    apply_min_severity_override(&mut policy, min_severity);
    shk_core::masker::mask_from_policy(text, &policy, CLIPBOARD_LABEL)
}

/// Reads UTF-8 text from the OS clipboard. Non-text contents (e.g. images)
/// and an empty clipboard are treated as empty text.
fn read_clipboard_text() -> Result<String> {
    let mut clipboard = open_clipboard()?;
    match clipboard.get_text() {
        Ok(text) => Ok(text),
        Err(arboard::Error::ContentNotAvailable) => Ok(String::new()),
        Err(err) => {
            Err(CliExit::message(2, format!("unable to read clipboard text: {err}")).into())
        }
    }
}

/// Hidden `shk clipboard hold` entry point: reads text from stdin and keeps
/// the clipboard contents alive. On X11/Wayland, arboard only retains the
/// clipboard while the owning process runs, so this blocks (detached from the
/// caller) until another application takes clipboard ownership.
pub fn hold() -> Result<()> {
    use std::io::Read as _;
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .context("read clipboard holder input")?;
    let result = hold_clipboard_text(&text);
    text.zeroize();
    result
}

#[cfg(target_os = "linux")]
fn hold_clipboard_text(text: &str) -> Result<()> {
    use arboard::SetExtLinux;
    let mut clipboard = open_clipboard()?;
    clipboard
        .set()
        .wait()
        .text(text)
        .map_err(|err| CliExit::message(2, format!("unable to write clipboard text: {err}")))?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn hold_clipboard_text(text: &str) -> Result<()> {
    set_clipboard_text_direct(text)
}

#[cfg(target_os = "linux")]
fn write_clipboard_text(text: &str) -> Result<()> {
    // Without a holder process the X11/Wayland clipboard goes empty as soon
    // as this CLI exits (unless a clipboard manager is running). Spawn a
    // detached `shk clipboard hold` that owns the contents until another
    // application replaces them.
    let spawned = spawn_clipboard_holder(text);
    if spawned.is_err() {
        // Better a process-lifetime write than failing outright.
        return set_clipboard_text_direct(text);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_clipboard_holder(text: &str) -> Result<()> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe().context("locate shk binary for clipboard holder")?;
    let mut child = Command::new(exe)
        .args(["clipboard", "hold"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn clipboard holder process")?;
    child
        .stdin
        .take()
        .context("clipboard holder stdin unavailable")?
        .write_all(text.as_bytes())
        .context("send text to clipboard holder")?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn write_clipboard_text(text: &str) -> Result<()> {
    set_clipboard_text_direct(text)
}

fn set_clipboard_text_direct(text: &str) -> Result<()> {
    let mut clipboard = open_clipboard()?;
    clipboard
        .set_text(text)
        .map_err(|err| CliExit::message(2, format!("unable to write clipboard text: {err}")))?;
    Ok(())
}

fn open_clipboard() -> Result<arboard::Clipboard> {
    arboard::Clipboard::new()
        .map_err(|err| CliExit::message(2, format!("clipboard unavailable: {err}")).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Synthetic OpenAI-style key assembled at runtime so this source file
    /// never contains raw secret-shaped text (AGENTS.md security hygiene).
    fn synthetic_key_text() -> String {
        format!("token sk-proj-{}\n", "abcdefghijklmnopqrstuvwxyz0123456789")
    }

    #[test]
    fn scan_clipboard_text_detects_secret_above_threshold() {
        let root = tempdir().expect("temp dir");

        let res = scan_clipboard_text(root.path(), &synthetic_key_text(), false, None)
            .expect("clipboard text scan");

        assert!(
            res.findings.iter().any(|f| f.file == CLIPBOARD_LABEL),
            "findings should use the clipboard label: {:?}",
            res.findings
        );
        assert!(
            res.should_fail(),
            "synthetic key should meet the fail threshold"
        );
    }

    #[test]
    fn scan_clipboard_text_passes_on_clean_text() {
        let root = tempdir().expect("temp dir");

        let res = scan_clipboard_text(root.path(), "just a harmless note\n", false, None)
            .expect("clipboard text scan");

        assert!(res.findings.is_empty(), "{:?}", res.findings);
        assert!(!res.should_fail());
    }

    #[test]
    fn mask_clipboard_text_redacts_email() {
        let root = tempdir().expect("temp dir");
        let text = "contact: user@example.com\n";

        let (masked, findings) =
            mask_clipboard_text(root.path(), text, None, None).expect("clipboard mask");

        assert!(
            !masked.contains("user@example.com"),
            "masked output must not contain the raw email: {masked}"
        );
        assert!(
            findings.iter().any(|f| f.file == CLIPBOARD_LABEL),
            "{findings:?}"
        );
    }

    #[test]
    fn scan_clipboard_output_json_redacts_and_marks_failure() {
        let root = tempdir().expect("temp dir");
        let inv = ClipboardScanInvocation {
            json: true,
            verbose: false,
            fail_on: None,
            color_enabled: false,
        };

        let out = scan_clipboard_output(root.path(), &synthetic_key_text(), &inv)
            .expect("clipboard scan output");

        assert!(out.should_fail);
        let json: serde_json::Value = serde_json::from_str(&out.stdout).expect("json output");
        assert_eq!(json["scanned_paths"][0], CLIPBOARD_LABEL);
        assert_eq!(json["findings"][0]["redacted_value"], "[REDACTED]");
        assert!(!out.stdout.contains("abcdefghijklmnopqrstuvwxyz0123456789"));
    }

    #[test]
    fn scan_clipboard_output_human_reports_clean_summary() {
        let root = tempdir().expect("temp dir");
        let inv = ClipboardScanInvocation {
            json: false,
            verbose: false,
            fail_on: None,
            color_enabled: false,
        };

        let out = scan_clipboard_output(root.path(), "just a harmless note\n", &inv)
            .expect("clipboard scan output");

        assert!(!out.should_fail);
        assert!(out.stdout.contains("No findings"));
    }

    #[test]
    fn scan_clipboard_output_respects_fail_on_override() {
        let root = tempdir().expect("temp dir");
        let inv = ClipboardScanInvocation {
            json: false,
            verbose: false,
            fail_on: Some(SeverityArg::Critical),
            color_enabled: false,
        };

        let out = scan_clipboard_output(root.path(), &synthetic_key_text(), &inv)
            .expect("clipboard scan output");

        assert!(!out.should_fail);
        assert!(out.stdout.contains("below threshold critical"));
    }

    #[test]
    fn mask_clipboard_output_json_contains_masked_content() {
        let root = tempdir().expect("temp dir");
        let inv = ClipboardMaskInvocation {
            json: true,
            write: false,
            redaction: None,
            min_severity: None,
        };

        let out = mask_clipboard_output(root.path(), "contact: user@example.com\n", &inv)
            .expect("clipboard mask output");

        let json: serde_json::Value = serde_json::from_str(&out.stdout).expect("json output");
        let masked = json["masked_content"].as_str().unwrap_or_default();
        assert!(masked.contains("[REDACTED]"), "{masked}");
        assert!(!masked.contains("user@example.com"), "{masked}");
        assert!(!out.masked.contains("user@example.com"), "{}", out.masked);
    }

    #[test]
    fn mask_clipboard_output_write_mode_prints_metadata_only() {
        let root = tempdir().expect("temp dir");
        let inv = ClipboardMaskInvocation {
            json: false,
            write: true,
            redaction: None,
            min_severity: None,
        };

        let out = mask_clipboard_output(root.path(), "contact: user@example.com\n", &inv)
            .expect("clipboard mask output");

        assert!(out.stdout.contains("Replaced clipboard with masked text"));
        assert!(out.stdout.contains("1 finding(s)"));
        assert!(!out.stdout.contains("user@example.com"));
        assert!(!out.stdout.contains("[REDACTED]"));
    }

    #[test]
    fn mask_clipboard_output_human_prints_redacted_text() {
        let root = tempdir().expect("temp dir");
        let inv = ClipboardMaskInvocation {
            json: false,
            write: false,
            redaction: Some(RedactionMode::Partial),
            min_severity: None,
        };

        let out = mask_clipboard_output(root.path(), &synthetic_key_text(), &inv)
            .expect("clipboard mask output");

        assert!(out.stdout.contains("sk-p[REDACTED]6789"), "{}", out.stdout);
        assert!(!out.stdout.contains("abcdefghijklmnopqrstuvwxyz0123456789"));
    }
}
