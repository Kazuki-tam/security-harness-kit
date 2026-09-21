use base64::{Engine as _, engine::general_purpose::STANDARD};
use minisign_verify::PublicKey;

pub fn validate_release_key(
    is_release: bool,
    allow_missing: bool,
    key: Option<&str>,
) -> Result<(), &'static str> {
    if !is_release {
        return Ok(());
    }
    let Some(key) = key.map(str::trim).filter(|value| !value.is_empty()) else {
        return if allow_missing {
            Ok(())
        } else {
            Err(
                "release build requires TAURI_UPDATER_PUBKEY; set SHK_ALLOW_MISSING_UPDATER_PUBKEY=1 only for local/non-distribution builds",
            )
        };
    };
    // Match compile_time_updater_pubkey's normalization in the application.
    let decoded = STANDARD
        .decode(key)
        .map_err(|_| "TAURI_UPDATER_PUBKEY must be base64-encoded Minisign public-key text")?;
    let text = std::str::from_utf8(&decoded)
        .map_err(|_| "TAURI_UPDATER_PUBKEY must decode to UTF-8 public-key text")?;
    PublicKey::decode(text)
        .map_err(|_| "TAURI_UPDATER_PUBKEY contains an invalid Minisign public key")?;
    Ok(())
}
