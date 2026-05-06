use crate::args::{AiTool, RedactionMode};
use crate::hook_output;
use anyhow::{Context, Result, bail};
use shk_core::finding::Finding;
use shk_core::masker::MaskJsonOutput;
use shk_core::policy::Policy;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub fn run(
    project_root: &Path,
    file: Option<PathBuf>,
    json: bool,
    output: Option<PathBuf>,
    redaction: Option<RedactionMode>,
    hook_mode: Option<AiTool>,
    post: bool,
) -> Result<()> {
    if let Some(tool) = hook_mode {
        if file.is_some() || output.is_some() || json {
            bail!("`mask --hook-mode` cannot be combined with FILE, `--output`, or `--json`");
        }
        return run_hook_mode(project_root, tool, post);
    }
    if post {
        bail!("`mask --post` requires `--hook-mode <tool>`");
    }

    let (rel_label, mut bytes) = read_mask_input(file.as_ref())?;
    let (mut policy, _) = Policy::load_from_dir(project_root)?;
    apply_redaction_override(&mut policy, redaction);

    if is_binary_or_non_utf8(&bytes, policy.scan.binary_detection_bytes) {
        let findings = vec![binary_passthrough_finding(&rel_label)];
        let result: Result<()> = if json {
            let out = MaskJsonOutput {
                masked_content: "[BINARY_PASSTHROUGH]".into(),
                findings,
            };
            match serde_json::to_string_pretty(&out) {
                Ok(s) => {
                    println!("{s}");
                    Ok(())
                }
                Err(e) => Err(e.into()),
            }
        } else {
            match io::stdout().write_all(&bytes) {
                Ok(()) => Ok(()),
                Err(e) => Err(e.into()),
            }
        };
        let output_result: Result<()> = if let Some(outp) = output {
            match fs::write(&outp, &bytes) {
                Ok(()) => Ok(()),
                Err(e) => Err(e.into()),
            }
        } else {
            Ok(())
        };
        bytes.zeroize();
        result?;
        output_result?;
        return Ok(());
    }

    let mut buf = String::from_utf8(std::mem::take(&mut bytes)).expect("checked above");
    let mask_result = shk_core::masker::mask_from_policy(&buf, &policy, &rel_label);
    buf.zeroize();
    let (masked, findings) = mask_result?;
    if json {
        let out = MaskJsonOutput {
            masked_content: masked.clone(),
            findings,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print!("{masked}");
    }
    if let Some(outp) = output {
        fs::write(&outp, masked)?;
    }
    Ok(())
}

fn apply_redaction_override(policy: &mut Policy, redaction: Option<RedactionMode>) {
    if let Some(mode) = redaction {
        policy.mask.redaction = match mode {
            RedactionMode::Full => "full",
            RedactionMode::Partial => "partial",
        }
        .into();
    }
}

fn read_mask_input(file: Option<&PathBuf>) -> Result<(String, Vec<u8>)> {
    let mut bytes = Vec::new();
    let rel_label = if let Some(f) = file {
        let mut r = fs::File::open(f)?;
        r.read_to_end(&mut bytes)?;
        f.to_string_lossy().to_string()
    } else {
        io::stdin().read_to_end(&mut bytes)?;
        "<stdin>".into()
    };
    Ok((rel_label, bytes))
}

fn run_hook_mode(cwd: &Path, tool: AiTool, post: bool) -> Result<()> {
    let mut stdin_raw = Vec::new();
    io::stdin().read_to_end(&mut stdin_raw)?;
    let mut stdin_str = String::from_utf8_lossy(&stdin_raw).to_string();
    stdin_raw.zeroize();
    let stdin_trim = stdin_str.trim();
    if stdin_trim.is_empty() {
        stdin_str.zeroize();
        bail!("mask hook-mode requires hook JSON payload on stdin");
    }

    let repo_root = resolve_repo_root(cwd);
    let hook_body_result = shk_integrations::stdin_to_hook_body(
        tool.integration_tool(),
        post,
        stdin_trim,
        cwd,
        &repo_root,
    );
    stdin_str.zeroize();
    let (disp, mut body) = hook_body_result?;
    let (policy, _) = Policy::load_from_dir(&repo_root)?;
    let mask_result = shk_core::masker::mask_from_policy(&body, &policy, &disp);
    body.zeroize();
    let (mut masked, findings) = mask_result.context("hook mask failed")?;

    println!(
        "{}",
        hook_output::mask_stdout(
            tool,
            post,
            findings.len(),
            (!findings.is_empty()).then_some(masked.as_str()),
        )
    );
    masked.zeroize();
    Ok(())
}

fn resolve_repo_root(cwd: &Path) -> PathBuf {
    shk_core::git::discover_repo_root(cwd)
        .and_then(|p| std::fs::canonicalize(&p).ok().or(Some(p)))
        .unwrap_or_else(|| std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf()))
}

fn is_binary_or_non_utf8(bytes: &[u8], binary_detection_bytes: usize) -> bool {
    let take = binary_detection_bytes.min(bytes.len());
    bytes[..take].contains(&0) || std::str::from_utf8(bytes).is_err()
}

fn binary_passthrough_finding(file: &str) -> Finding {
    Finding {
        rule_id: "mask.binary_passthrough".into(),
        severity: "info".into(),
        kind: "ignore".into(),
        file: file.into(),
        line: 1,
        column: 1,
        message: "Binary or non-UTF-8 input was passed through unchanged and not scanned".into(),
        redacted_value: "[REDACTED]".into(),
        confidence: 1.0,
        context_before: vec![],
        context_after: vec![],
    }
}
