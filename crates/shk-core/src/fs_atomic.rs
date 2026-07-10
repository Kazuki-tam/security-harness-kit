use anyhow::{Context, Result, anyhow};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

/// Persist a completed sibling temporary file, atomically replacing `path`.
///
/// `tempfile` implements replacement with the platform primitive, including
/// `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` on Windows. Do not emulate this by
/// deleting the destination first: that creates a data-loss window.
pub fn persist_named_temp_file(tmp: NamedTempFile, path: &Path) -> Result<()> {
    tmp.persist(path)
        .map(|_| ())
        .map_err(|err| anyhow!("write {}: {}", path.display(), err.error))
}

/// Persist a completed sibling temporary file only when `path` does not exist.
pub fn persist_named_temp_file_noclobber(tmp: NamedTempFile, path: &Path) -> Result<()> {
    tmp.persist_noclobber(path)
        .map(|_| ())
        .map_err(|err| anyhow!("write {}: {}", path.display(), err.error))
}

/// Writes `body` through a sibling temporary file and atomically replaces
/// `path`, preserving existing destination permissions when present.
pub fn write_atomic(path: &Path, body: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = NamedTempFile::new_in(parent)
        .with_context(|| format!("create temp file in {}", parent.display()))?;
    tmp.write_all(body)
        .with_context(|| format!("write temp output for {}", path.display()))?;
    tmp.flush()
        .with_context(|| format!("flush temp output for {}", path.display()))?;
    if let Ok(metadata) = std::fs::metadata(path) {
        std::fs::set_permissions(tmp.path(), metadata.permissions())
            .with_context(|| format!("preserve permissions for {}", path.display()))?;
    }
    persist_named_temp_file(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        write_atomic(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn atomically_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        std::fs::write(&path, "old").unwrap();
        write_atomic(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn noclobber_preserves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        std::fs::write(&path, "old").unwrap();
        let mut tmp = NamedTempFile::new_in(dir.path()).unwrap();
        tmp.write_all(b"new").unwrap();

        assert!(persist_named_temp_file_noclobber(tmp, &path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
    }

    #[test]
    fn does_not_leave_temp_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        write_atomic(&path, b"data").unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn overwriting_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("script.sh");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        write_atomic(&path, b"new").unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}
