use crate::args::RedactionMode;
use anyhow::Result;
use shk_core::finding::Finding;
use shk_core::masker::MaskJsonOutput;
use shk_core::policy::Policy;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub fn run(
    project_root: &Path,
    file: Option<PathBuf>,
    json: bool,
    output: Option<PathBuf>,
    redaction: Option<RedactionMode>,
) -> Result<()> {
    if matches!(redaction, Some(RedactionMode::Partial)) {
        eprintln!("Note: partial redaction is not yet implemented; using full line redaction.");
    }
    let (policy, _) = Policy::load_from_dir(project_root)?;
    let mut bytes = Vec::new();
    let rel_label = if let Some(ref f) = file {
        let mut r = fs::File::open(f)?;
        r.read_to_end(&mut bytes)?;
        f.to_string_lossy().to_string()
    } else {
        io::stdin().read_to_end(&mut bytes)?;
        "<stdin>".into()
    };

    if is_binary_or_non_utf8(&bytes, policy.scan.binary_detection_bytes) {
        let findings = vec![binary_passthrough_finding(&rel_label)];
        if json {
            let out = MaskJsonOutput {
                masked_content: "[BINARY_PASSTHROUGH]".into(),
                findings,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            io::stdout().write_all(&bytes)?;
        }
        if let Some(outp) = output {
            fs::write(&outp, &bytes)?;
        }
        return Ok(());
    }

    let buf = String::from_utf8(bytes).expect("checked above");
    let (masked, findings) = shk_core::masker::mask_from_policy(&buf, &policy, &rel_label)?;
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
