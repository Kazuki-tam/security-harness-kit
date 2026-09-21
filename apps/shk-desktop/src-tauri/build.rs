mod updater_validation;

fn main() {
    println!("cargo:rerun-if-env-changed=TAURI_UPDATER_PUBKEY");
    println!("cargo:rerun-if-env-changed=SHK_ALLOW_MISSING_UPDATER_PUBKEY");
    assert_updater_pubkey_for_release();
    tauri_build::build();
}

/// A missing or malformed verification key makes signed updates unusable.
/// Validate with the same parser as the updater before distributing a release.
fn assert_updater_pubkey_for_release() {
    let is_release = std::env::var("PROFILE").as_deref() == Ok("release");
    if !is_release {
        return;
    }
    let public_key = std::env::var("TAURI_UPDATER_PUBKEY").ok();
    let explicitly_allowed = std::env::var("SHK_ALLOW_MISSING_UPDATER_PUBKEY")
        .map(|v| v == "1")
        .unwrap_or(false);
    if let Err(message) = updater_validation::validate_release_key(
        is_release,
        explicitly_allowed,
        public_key.as_deref(),
    ) {
        panic!("{message}");
    }
}
