#[path = "../updater_validation.rs"]
mod updater_validation;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use updater_validation::validate_release_key;

#[test]
fn accepts_the_public_example_from_minisign_verify_documentation() {
    // Public verification material from minisign-verify's documentation.
    let text = "untrusted comment: test public key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n";
    let encoded = STANDARD.encode(text);
    assert!(validate_release_key(true, false, Some(&encoded)).is_ok());
    assert!(validate_release_key(true, false, Some(&format!(" {encoded}\n"))).is_ok());
}

#[test]
fn missing_keys_require_an_explicit_non_distribution_override() {
    for key in [None, Some(""), Some(" \n")] {
        assert!(validate_release_key(true, false, key).is_err());
        assert!(validate_release_key(true, true, key).is_ok());
        assert!(validate_release_key(false, false, key).is_ok());
    }
}

#[test]
fn malformed_keys_fail_even_with_the_missing_key_override() {
    for key in [
        "invalid-base64".to_owned(),
        STANDARD.encode([0xff]),
        STANDARD.encode("not a Minisign key"),
    ] {
        for allow_missing in [false, true] {
            assert!(validate_release_key(true, allow_missing, Some(&key)).is_err());
        }
    }
}
