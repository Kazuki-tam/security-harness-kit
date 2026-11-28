//! Helpers shared by the unit tests.

use crate::model::Index;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/deps")
}

/// `(file name, content)` of every file in a fixture directory, sorted.
pub fn fixture_files(relative: &str) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(fixtures_dir().join(relative))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

/// A deflated ZIP archive of `files`, like the OSV `all.zip` dump.
pub fn zip_of(files: &[(String, Vec<u8>)]) -> Cursor<Vec<u8>> {
    zip_with(files, zip::CompressionMethod::Deflated)
}

pub fn zip_with(files: &[(String, Vec<u8>)], method: zip::CompressionMethod) -> Cursor<Vec<u8>> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default().compression_method(method);
    for (name, content) in files {
        writer.start_file(name.as_str(), options).unwrap();
        writer.write_all(content).unwrap();
    }
    let mut archive = writer.finish().unwrap();
    archive.set_position(0);
    archive
}

/// The synthetic records, without the entry that is not JSON.
pub fn synthetic_files() -> Vec<(String, Vec<u8>)> {
    fixture_files("osv/synthetic")
        .into_iter()
        .filter(|(name, _)| !name.starts_with("BROKEN"))
        .collect()
}

pub fn synthetic_index() -> Index {
    crate::build_index(zip_of(&synthetic_files()))
        .unwrap()
        .index
}

pub fn real_index() -> Index {
    crate::build_index(zip_of(&fixture_files("osv/real")))
        .unwrap()
        .index
}

/// The text of `fixtures/deps/lockfiles/<case>.lock`.
pub fn lockfile_text(case: &str) -> String {
    let path = fixtures_dir().join(format!("lockfiles/{case}.lock"));
    std::fs::read_to_string(path).unwrap()
}

/// Writes a file below `root`, creating its directories.
pub fn write_file(root: &Path, relative: &str, content: &[u8]) -> PathBuf {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, content).unwrap();
    path
}
