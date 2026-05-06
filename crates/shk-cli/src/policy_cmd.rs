use anyhow::{Result, bail};
use shk_core::policy::default_policy_toml;
use std::fs;
use std::path::Path;

pub fn init(root: &Path, strict: bool, force: bool) -> Result<()> {
    let p = root.join("shk.toml");
    if p.exists() && !force {
        bail!("{} already exists (use --force to overwrite)", p.display());
    }
    fs::write(&p, default_policy_toml(strict))?;
    println!("Wrote {}", p.display());
    Ok(())
}
