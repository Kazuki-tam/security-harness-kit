use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use minisign_verify::{PublicKey, Signature};
use std::{fs, path::Path};

/// Verify the actual payload/key pairing before release artifacts can be uploaded.
/// Tauri wraps both Minisign public keys and signature text in Base64.
pub fn verify(directory: &Path, encoded_key: &str) -> Result<usize> {
    let key_text = decode_text(encoded_key).context("invalid updater public key encoding")?;
    let key = PublicKey::decode(&key_text).context("invalid updater public key")?;
    let mut signatures = Vec::new();
    for entry in fs::read_dir(directory).context("read updater artifact directory")? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        // These are the payload types selected by generate-tauri-latest-json.sh.
        let update_payload =
            name.ends_with(".app.tar.gz") || name.ends_with(".AppImage") || name.ends_with(".exe");
        if update_payload {
            require_regular_file(&path)?;
            require_regular_file(&path.with_file_name(format!("{name}.sig")))
                .context("updater payload is missing its signature")?;
        }
        if name.ends_with(".sig") {
            signatures.push(path);
        }
    }
    if signatures.is_empty() {
        bail!("no updater signatures found");
    }
    signatures.sort();
    for signature_path in &signatures {
        require_regular_file(signature_path)?;
        let payload = signature_path.with_extension("");
        require_regular_file(&payload).context("signature has no regular payload")?;
        let encoded = fs::read_to_string(signature_path).context("read updater signature")?;
        let text = decode_text(&encoded).context("invalid updater signature encoding")?;
        let signature = Signature::decode(&text).context("invalid updater signature")?;
        let bytes = fs::read(&payload).context("read updater payload")?;
        key.verify(&bytes, &signature, true)
            .context("updater signature does not match the payload and release public key")?;
    }
    Ok(signatures.len())
}

fn decode_text(encoded: &str) -> Result<String> {
    let bytes = STANDARD.decode(encoded.trim()).context("invalid Base64")?;
    String::from_utf8(bytes).context("invalid UTF-8")
}

fn require_regular_file(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        bail!("updater artifacts must be regular files, not symlinks or directories");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public sample signature and verification key from minisign-verify's docs.
    const PUBLIC_KEY: &str = "untrusted comment: public example\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n";
    const SIGNATURE: &str = "untrusted comment: public example\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1633700835\tfile:test\tprehashed\nwLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJpIidRJnp94ABQkJAgAooBQ==";

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("sample.app.tar.gz"), b"test").unwrap();
        fs::write(
            dir.path().join("sample.app.tar.gz.sig"),
            STANDARD.encode(SIGNATURE),
        )
        .unwrap();
        dir
    }

    #[test]
    fn verifies_public_sample_and_rejects_modified_payload() {
        let dir = fixture();
        let key = STANDARD.encode(PUBLIC_KEY);
        assert_eq!(verify(dir.path(), &key).unwrap(), 1);
        fs::write(dir.path().join("sample.app.tar.gz"), b"tampered").unwrap();
        assert!(verify(dir.path(), &key).is_err());
    }

    #[test]
    fn rejects_wrong_key_and_malformed_signature() {
        let dir = fixture();
        let mut altered = STANDARD.decode(PUBLIC_KEY.lines().nth(1).unwrap()).unwrap();
        altered[10] ^= 1;
        let wrong_key = STANDARD.encode(format!(
            "untrusted comment: public example\n{}\n",
            STANDARD.encode(altered)
        ));
        assert!(verify(dir.path(), &wrong_key).is_err());
        fs::write(dir.path().join("sample.app.tar.gz.sig"), "invalid").unwrap();
        assert!(verify(dir.path(), &STANDARD.encode(PUBLIC_KEY)).is_err());
    }

    #[test]
    fn rejects_missing_signatures_payloads_and_empty_directories() {
        let key = STANDARD.encode(PUBLIC_KEY);
        let dir = tempfile::tempdir().unwrap();
        assert!(verify(dir.path(), &key).is_err());
        fs::write(dir.path().join("sample.AppImage"), b"test").unwrap();
        assert!(verify(dir.path(), &key).is_err());
        let dir = fixture();
        fs::remove_file(dir.path().join("sample.app.tar.gz")).unwrap();
        assert!(verify(dir.path(), &key).is_err());
    }

    #[test]
    fn rejects_invalid_key_encodings() {
        let dir = fixture();
        for key in [
            "invalid".to_owned(),
            STANDARD.encode([0xff]),
            STANDARD.encode("invalid"),
        ] {
            assert!(verify(dir.path(), &key).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_payloads() {
        let dir = fixture();
        fs::rename(
            dir.path().join("sample.app.tar.gz"),
            dir.path().join("original"),
        )
        .unwrap();
        std::os::unix::fs::symlink("original", dir.path().join("sample.app.tar.gz")).unwrap();
        assert!(verify(dir.path(), &STANDARD.encode(PUBLIC_KEY)).is_err());
    }
}
