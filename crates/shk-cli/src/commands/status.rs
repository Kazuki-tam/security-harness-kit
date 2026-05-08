use crate::doctor;
use crate::version_check::{self, VersionStatus};
use anyhow::Result;
use shk_core::policy::Policy;
use std::path::Path;

pub fn run(root: &Path) -> Result<()> {
    println!("status:");
    print_policy(root)?;
    print_pre_commit(root);
    print_ai_hooks(root);
    print_skills();
    print_scan_hint();
    print_version();
    Ok(())
}

fn print_policy(root: &Path) -> Result<()> {
    let (policy, path) = Policy::load_from_dir(root)?;
    match path {
        Some(path) => println!(
            "  [ok]   shk.toml       found ({}, scan fail-on {})",
            path.display(),
            policy.scan_fail_on().as_str()
        ),
        None => println!("  [warn] shk.toml       not found (run `shk init --strict`)"),
    }
    Ok(())
}

fn print_pre_commit(root: &Path) {
    if doctor::has_shk_pre_commit(root) {
        println!("  [ok]   pre-commit     installed");
    } else {
        println!("  [warn] pre-commit     not installed (run `shk hooks install`)");
    }
}

fn print_ai_hooks(root: &Path) {
    if doctor::has_managed_ai_hooks(root) {
        println!("  [ok]   ai hooks       managed hooks present");
    } else {
        println!("  [warn] ai hooks       not found (run `shk hooks install-ai`)");
    }
}

fn print_skills() {
    let entries = crate::commands::skills::status_entries();
    let installed = entries.iter().filter(|entry| entry.installed).count();
    if installed > 0 {
        println!(
            "  [ok]   skills         {installed}/{} installed",
            entries.len()
        );
    } else {
        println!("  [info] skills         not installed (run `shk skills install`)");
    }
}

fn print_scan_hint() {
    println!("  [info] scan           last run not tracked yet (run `shk scan .`)");
}

fn print_version() {
    match version_check::check_latest_version() {
        Ok(check) => match check.status() {
            VersionStatus::Current => {
                println!("  [ok]   version        {} is current", check.current());
            }
            VersionStatus::UpdateAvailable => {
                println!(
                    "  [warn] version        update available: {} -> {}",
                    check.current(),
                    check.latest_tag()
                );
                println!(
                    "         update         rerun the install script or use your package manager"
                );
                println!("         release        {}", check.release_url());
            }
            VersionStatus::LocalNewer => {
                println!(
                    "  [info] version        {} is newer than latest release {}",
                    check.current(),
                    check.latest_tag()
                );
            }
            VersionStatus::Unknown => {
                println!(
                    "  [info] version        latest release differs: local {}, latest {}",
                    check.current(),
                    check.latest_tag()
                );
                println!("         release        {}", check.release_url());
            }
        },
        Err(err) => {
            println!("  [info] version        unknown (could not check latest release: {err})");
        }
    }
}
