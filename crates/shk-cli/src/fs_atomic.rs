use anyhow::{Context, Result, anyhow};
use std::io::{ErrorKind, Write};
use std::path::Path;
use tempfile::NamedTempFile;

/// Writes `body` to `path` via a sibling temp file + rename so a crash mid-write
/// never leaves a truncated or corrupted file behind.
pub fn write_atomic(path: &Path, body: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = NamedTempFile::new_in(parent)
        .with_context(|| format!("create temp file in {}", parent.display()))?;
    tmp.write_all(body)
        .with_context(|| format!("write temp output for {}", path.display()))?;
    tmp.flush()
        .with_context(|| format!("flush temp output for {}", path.display()))?;

    match tmp.persist(path) {
        Ok(_) => Ok(()),
        // Windows cannot rename over an existing file; remove and retry once.
        Err(err) if err.error.kind() == ErrorKind::AlreadyExists => {
            let tmp = err.file;
            std::fs::remove_file(path).with_context(|| format!("replace {}", path.display()))?;
            tmp.persist(path)
                .map(|_| ())
                .map_err(|err| anyhow!("write {}: {}", path.display(), err.error))
        }
        Err(err) => Err(anyhow!("write {}: {}", path.display(), err.error)),
    }
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
    fn overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        std::fs::write(&path, "old").unwrap();
        write_atomic(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn does_not_leave_temp_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        write_atomic(&path, b"data").unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }
}
