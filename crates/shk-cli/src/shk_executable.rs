use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn candidates_in_dirs<I, P>(dirs: I, pathext: Option<&OsStr>) -> Vec<PathBuf>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let names = executable_names(pathext);
    dirs.into_iter()
        .flat_map(|dir| {
            names
                .iter()
                .map(move |name| dir.as_ref().join(name))
                .filter(|candidate| is_executable_file(candidate))
        })
        .collect()
}

#[cfg(windows)]
fn executable_names(pathext: Option<&OsStr>) -> Vec<OsString> {
    let pathext = pathext
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());
    let mut names = Vec::new();
    for extension in pathext.split(';') {
        let extension = extension.trim();
        if extension.is_empty() {
            continue;
        }
        let extension = if extension.starts_with('.') {
            extension.to_ascii_lowercase()
        } else {
            format!(".{}", extension.to_ascii_lowercase())
        };
        let name = OsString::from(format!("shk{extension}"));
        if !names.iter().any(|existing| existing == &name) {
            names.push(name);
        }
    }
    names
}

#[cfg(not(windows))]
fn executable_names(_pathext: Option<&OsStr>) -> Vec<OsString> {
    vec![OsString::from("shk")]
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(not(any(unix, windows)))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}
