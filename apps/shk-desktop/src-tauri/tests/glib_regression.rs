#![cfg(target_os = "linux")]

use glib::variant::ToVariant;

// Run in release mode too: optimization exposes RUSTSEC-2024-0429's invalid
// immutable out-parameter even when debug tests happen to pass.
#[test]
fn variant_string_iterator_preserves_all_traversal_modes() {
    let values = ["alpha", "日本語", "", "omega"];
    let variant = values.to_variant();
    assert_eq!(
        variant.array_iter_str().unwrap().collect::<Vec<_>>(),
        values
    );
    assert_eq!(
        variant.array_iter_str().unwrap().rev().collect::<Vec<_>>(),
        values.into_iter().rev().collect::<Vec<_>>()
    );
    assert_eq!(variant.array_iter_str().unwrap().last(), Some("omega"));
    assert_eq!(variant.array_iter_str().unwrap().nth(1), Some("日本語"));
    assert_eq!(
        variant.array_iter_str().unwrap().nth_back(2),
        Some("日本語")
    );
    let mut iter = variant.array_iter_str().unwrap();
    assert_eq!(iter.next(), Some("alpha"));
    assert_eq!(iter.next_back(), Some("omega"));
    assert_eq!(iter.next(), Some("日本語"));
    assert_eq!(iter.next_back(), Some(""));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next_back(), None);
}
