fn main() {
    println!("cargo:rerun-if-env-changed=TAURI_UPDATER_PUBKEY");
    println!("cargo:rerun-if-env-changed=SHK_ALLOW_MISSING_UPDATER_PUBKEY");
    assert_updater_pubkey_for_release();
    tauri_build::build();
}

/// Release binaries must not ship with the updater accepting unsigned
/// payloads. Fail the build instead of silently falling back to "no pubkey"
/// when the TAURI_UPDATER_PUBKEY secret is missing or empty.
fn assert_updater_pubkey_for_release() {
    let is_release = std::env::var("PROFILE").as_deref() == Ok("release");
    if !is_release {
        return;
    }
    let pubkey_present = std::env::var("TAURI_UPDATER_PUBKEY")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let explicitly_allowed = std::env::var("SHK_ALLOW_MISSING_UPDATER_PUBKEY")
        .map(|v| v == "1")
        .unwrap_or(false);
    if !pubkey_present && !explicitly_allowed {
        panic!(
            "release build without TAURI_UPDATER_PUBKEY: the updater would ship without \
             signature verification. Set TAURI_UPDATER_PUBKEY, or set \
             SHK_ALLOW_MISSING_UPDATER_PUBKEY=1 for local/non-distribution builds."
        );
    }
}
