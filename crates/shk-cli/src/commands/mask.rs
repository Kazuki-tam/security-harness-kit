use crate::args::RedactionMode;
use anyhow::Result;
use shk_core::masker::MaskJsonOutput;
use shk_core::policy::Policy;
use std::fs;
use std::io::{self, Read};
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
    let mut buf = String::new();
    let rel_label = if let Some(ref f) = file {
        let mut r = fs::File::open(f)?;
        r.read_to_string(&mut buf)?;
        f.to_string_lossy().to_string()
    } else {
        io::stdin().read_to_string(&mut buf)?;
        "<stdin>".into()
    };
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
