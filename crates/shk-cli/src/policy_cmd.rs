use crate::{fs_atomic, safety};
use anyhow::{Result, bail};
use shk_core::policy::default_policy_toml;
use std::path::Path;

pub fn init(root: &Path, strict: bool, force: bool) -> Result<()> {
    let p = root.join("shk.toml");
    if p.exists() && !force {
        bail!("{} already exists (use --force to overwrite)", p.display());
    }
    safety::ensure_write_path_within(root, &p)?;
    fs_atomic::write_atomic(&p, default_policy_toml(strict).as_bytes())?;
    println!("Wrote {}", p.display());
    Ok(())
}
