use crate::{fs_atomic, safety};
use anyhow::{Context, Result};
use ignore::WalkBuilder;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const NPMRC_FILE: &str = ".npmrc";
const PNPM_WORKSPACE_FILE: &str = "pnpm-workspace.yaml";
const YARNRC_FILE: &str = ".yarnrc.yml";
const BUNFIG_FILE: &str = "bunfig.toml";
const PACKAGE_JSON: &str = "package.json";
const PACKAGE_LOCK_FILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
];
const IGNORE_SCRIPTS_KEY: &str = "ignore-scripts";
const MIN_RELEASE_AGE_KEY: &str = "min-release-age";
const MINIMUM_RELEASE_AGE_KEY: &str = "minimumReleaseAge";
const MIN_RELEASE_AGE_DAYS: u64 = 7;
const PNPM_MIN_RELEASE_AGE_MINUTES: u64 = MIN_RELEASE_AGE_DAYS * 24 * 60;
const BUN_MIN_RELEASE_AGE_SECONDS: u64 = MIN_RELEASE_AGE_DAYS * 24 * 60 * 60;
const YARN_MIN_RELEASE_AGE_KEY: &str = "npmMinimalAgeGate";
const YARN_MIN_RELEASE_AGE_MINUTES: u64 = MIN_RELEASE_AGE_DAYS * 24 * 60;
const MANAGED_MARKER: &str = "# shk-managed npm-hardening";
const PNPM_SINGLE_PACKAGE_ENTRY: &str = "  - \".\"";
const DEPENDABOT_FILES: &[&str] = &[".github/dependabot.yml", ".github/dependabot.yaml"];
const RENOVATE_FILES: &[&str] = &[
    "renovate.json",
    "renovate.json5",
    ".github/renovate.json",
    ".github/renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
    ".renovaterc.json5",
];
const PACKAGE_WALK_SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "target",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NpmHardeningStatus {
    pub package_dirs: Vec<PathBuf>,
    pub root_project: bool,
    pub package_dirs_without_lockfile: Vec<PathBuf>,
    pub package_managers: Vec<PackageManager>,
    pub npmrc_path: PathBuf,
    pub pnpm_workspace_path: PathBuf,
    pub yarnrc_path: PathBuf,
    pub bunfig_path: PathBuf,
    pub ignore_scripts_ok: bool,
    pub min_release_age_ok: bool,
    pub min_release_age: Option<u64>,
    pub pnpm_min_release_age_ok: bool,
    pub pnpm_min_release_age_minutes: Option<u64>,
    pub yarn_min_release_age_ok: bool,
    pub yarn_min_release_age_minutes: Option<u64>,
    pub bun_min_release_age_ok: bool,
    pub bun_min_release_age_seconds: Option<u64>,
    pub dependabot: DependencyBotStatus,
    pub renovate: DependencyBotStatus,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
}

impl PackageManager {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DependencyBotStatus {
    pub config_path: Option<PathBuf>,
    pub configured: bool,
    pub cooldown_ok: bool,
    pub cooldown_days: Option<u64>,
}

impl NpmHardeningStatus {
    pub fn has_npm_projects(&self) -> bool {
        !self.package_dirs.is_empty()
    }

    pub fn ok(&self) -> bool {
        !self.has_npm_projects()
            || (self.package_scripts_ok()
                && self.age_gates_ok()
                && self.package_dirs_without_lockfile.is_empty()
                && self.dependency_bot_cooldown_ok())
    }

    pub fn package_scripts_ok(&self) -> bool {
        !self
            .package_managers
            .iter()
            .any(|manager| matches!(manager, PackageManager::Npm | PackageManager::Pnpm))
            || self.ignore_scripts_ok
    }

    pub fn age_gates_ok(&self) -> bool {
        self.package_managers.iter().all(|manager| match manager {
            PackageManager::Npm => self.min_release_age_ok,
            PackageManager::Pnpm => self.pnpm_min_release_age_ok,
            PackageManager::Yarn => self.yarn_min_release_age_ok,
            PackageManager::Bun => self.bun_min_release_age_ok,
        })
    }

    pub fn dependency_bot_cooldown_ok(&self) -> bool {
        self.dependabot.cooldown_ok || self.renovate.cooldown_ok
    }

    pub(crate) fn apply_paths(&self) -> Vec<&Path> {
        let mut paths = Vec::new();
        if self
            .package_managers
            .iter()
            .any(|manager| matches!(manager, PackageManager::Npm | PackageManager::Pnpm))
        {
            paths.push(self.npmrc_path.as_path());
        }
        if self.package_managers.contains(&PackageManager::Pnpm) {
            paths.push(self.pnpm_workspace_path.as_path());
        }
        if self.package_managers.contains(&PackageManager::Yarn) {
            paths.push(self.yarnrc_path.as_path());
        }
        if self.package_managers.contains(&PackageManager::Bun) {
            paths.push(self.bunfig_path.as_path());
        }
        paths
    }
}

pub fn status(root: &Path) -> NpmHardeningStatus {
    let package_dirs = find_package_dirs(root);
    let root_project = is_root_package_project(root, &package_dirs);
    let package_managers = detect_package_managers(root, &package_dirs);
    let npmrc_path = resolve_npmrc_path(root, &package_dirs);
    let pnpm_workspace_path = resolve_pnpm_workspace_path(root, &package_dirs);
    let yarnrc_path = root.join(YARNRC_FILE);
    let bunfig_path = root.join(BUNFIG_FILE);
    let npmrc = fs::read_to_string(&npmrc_path).unwrap_or_default();
    let ignore_scripts_ok = npmrc_bool(&npmrc, IGNORE_SCRIPTS_KEY).unwrap_or(false);
    let min_release_age = npmrc_u64(&npmrc, MIN_RELEASE_AGE_KEY);
    let min_release_age_ok = min_release_age
        .map(|days| days >= MIN_RELEASE_AGE_DAYS)
        .unwrap_or(false);
    let pnpm_min_release_age_minutes = yaml_top_level_u64(
        &fs::read_to_string(&pnpm_workspace_path).unwrap_or_default(),
        MINIMUM_RELEASE_AGE_KEY,
    );
    let pnpm_min_release_age_ok = pnpm_min_release_age_minutes
        .map(|minutes| minutes >= PNPM_MIN_RELEASE_AGE_MINUTES)
        .unwrap_or(false);
    let yarn_min_release_age_minutes = yaml_top_level_u64(
        &fs::read_to_string(&yarnrc_path).unwrap_or_default(),
        YARN_MIN_RELEASE_AGE_KEY,
    );
    let yarn_min_release_age_ok = yarn_min_release_age_minutes
        .map(|minutes| minutes >= YARN_MIN_RELEASE_AGE_MINUTES)
        .unwrap_or(false);
    let bun_min_release_age_seconds = bun_min_release_age_seconds(&bunfig_path);
    let bun_min_release_age_ok = bun_min_release_age_seconds
        .map(|seconds| seconds >= BUN_MIN_RELEASE_AGE_SECONDS)
        .unwrap_or(false);
    let package_dirs_without_lockfile = package_dirs
        .iter()
        .filter(|dir| !has_lockfile_for_package_dir(root, dir))
        .cloned()
        .collect();

    NpmHardeningStatus {
        package_dirs,
        root_project,
        package_dirs_without_lockfile,
        package_managers,
        npmrc_path,
        pnpm_workspace_path,
        yarnrc_path,
        bunfig_path,
        ignore_scripts_ok,
        min_release_age_ok,
        min_release_age,
        pnpm_min_release_age_ok,
        pnpm_min_release_age_minutes,
        yarn_min_release_age_ok,
        yarn_min_release_age_minutes,
        bun_min_release_age_ok,
        bun_min_release_age_seconds,
        dependabot: dependabot_status(root),
        renovate: renovate_status(root),
    }
}

fn is_root_package_project(root: &Path, package_dirs: &[PathBuf]) -> bool {
    package_dirs.iter().any(|dir| dir == Path::new("."))
        || root.join(PNPM_WORKSPACE_FILE).is_file()
        || root.join(YARNRC_FILE).is_file()
        || root.join(BUNFIG_FILE).is_file()
        || PACKAGE_LOCK_FILES
            .iter()
            .any(|name| root.join(name).is_file())
}

pub fn apply(root: &Path) -> Result<Option<NpmHardeningStatus>> {
    let before = status(root);
    if !before.has_npm_projects() {
        return Ok(None);
    }

    if before
        .package_managers
        .iter()
        .any(|manager| matches!(manager, PackageManager::Npm | PackageManager::Pnpm))
    {
        let existing = fs::read_to_string(&before.npmrc_path).unwrap_or_default();
        let updated = upsert_npmrc_settings(&existing, &before.package_managers);
        if updated != existing {
            write_managed(root, &before.npmrc_path, updated.as_bytes())?;
        }
    }
    if before.package_managers.contains(&PackageManager::Pnpm) {
        let existing = fs::read_to_string(&before.pnpm_workspace_path).unwrap_or_default();
        let updated = upsert_pnpm_workspace_settings(&existing);
        if updated != existing {
            write_managed(root, &before.pnpm_workspace_path, updated.as_bytes())?;
        }
    }
    if before.package_managers.contains(&PackageManager::Yarn) {
        let existing = fs::read_to_string(&before.yarnrc_path).unwrap_or_default();
        let updated = upsert_yaml_line(
            &existing,
            YARN_MIN_RELEASE_AGE_KEY,
            &YARN_MIN_RELEASE_AGE_MINUTES.to_string(),
        );
        if updated != existing {
            write_managed(root, &before.yarnrc_path, updated.as_bytes())?;
        }
    }
    if before.package_managers.contains(&PackageManager::Bun) {
        let existing = fs::read_to_string(&before.bunfig_path).unwrap_or_default();
        let updated = upsert_bunfig_min_release_age(&existing)
            .with_context(|| format!("update {}", before.bunfig_path.display()))?;
        if updated != existing {
            write_managed(root, &before.bunfig_path, updated.as_bytes())?;
        }
    }

    Ok(Some(status(root)))
}

pub fn unapply(root: &Path) -> Result<Option<NpmHardeningStatus>> {
    let before = status(root);
    if !before.has_npm_projects() {
        return Ok(None);
    }

    if before
        .package_managers
        .iter()
        .any(|manager| matches!(manager, PackageManager::Npm | PackageManager::Pnpm))
    {
        let existing = fs::read_to_string(&before.npmrc_path).unwrap_or_default();
        let updated = remove_npmrc_settings(&existing, &before.package_managers);
        if updated != existing {
            write_managed(root, &before.npmrc_path, updated.as_bytes())?;
        }
    }
    if before.package_managers.contains(&PackageManager::Pnpm) {
        let existing = fs::read_to_string(&before.pnpm_workspace_path).unwrap_or_default();
        let updated = remove_pnpm_workspace_settings(&existing);
        if updated != existing {
            if updated.trim().is_empty() {
                remove_managed(root, &before.pnpm_workspace_path)?;
            } else {
                write_managed(root, &before.pnpm_workspace_path, updated.as_bytes())?;
            }
        }
    }
    if before.package_managers.contains(&PackageManager::Yarn) {
        let existing = fs::read_to_string(&before.yarnrc_path).unwrap_or_default();
        let updated = remove_yaml_line(&existing, YARN_MIN_RELEASE_AGE_KEY);
        if updated != existing {
            write_managed(root, &before.yarnrc_path, updated.as_bytes())?;
        }
    }
    if before.package_managers.contains(&PackageManager::Bun) {
        let existing = fs::read_to_string(&before.bunfig_path).unwrap_or_default();
        let updated = remove_toml_table_key(&existing, "install", "minimumReleaseAge");
        if updated != existing {
            write_managed(root, &before.bunfig_path, updated.as_bytes())?;
        }
    }

    Ok(Some(status(root)))
}

fn write_managed(root: &Path, path: &Path, body: &[u8]) -> Result<()> {
    safety::ensure_writable_path_allowed(path)?;
    safety::ensure_write_path_within(root, path)?;
    fs_atomic::write_atomic(path, body)
}

fn remove_managed(root: &Path, path: &Path) -> Result<()> {
    safety::ensure_writable_path_allowed(path)?;
    safety::ensure_write_path_within(root, path)?;
    fs::remove_file(path).with_context(|| format!("remove {}", path.display()))
}

fn upsert_npmrc_settings(input: &str, package_managers: &[PackageManager]) -> String {
    let mut lines = input.lines().map(ToOwned::to_owned).collect::<Vec<_>>();
    upsert_npmrc_line(&mut lines, IGNORE_SCRIPTS_KEY, "true");
    if package_managers.contains(&PackageManager::Npm) {
        upsert_npmrc_line(
            &mut lines,
            MIN_RELEASE_AGE_KEY,
            &MIN_RELEASE_AGE_DAYS.to_string(),
        );
    }
    let mut output = lines.join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    output
}

fn remove_npmrc_settings(input: &str, package_managers: &[PackageManager]) -> String {
    let mut lines = input.lines().map(ToOwned::to_owned).collect::<Vec<_>>();
    remove_managed_key_lines(&mut lines, IGNORE_SCRIPTS_KEY, npmrc_line_key);
    if package_managers.contains(&PackageManager::Npm) {
        remove_managed_key_lines(&mut lines, MIN_RELEASE_AGE_KEY, npmrc_line_key);
    }
    trim_trailing_empty_lines(&mut lines);
    finish_lines(lines)
}

fn upsert_npmrc_line(lines: &mut Vec<String>, key: &str, value: &str) {
    let replacement = format!("{key}={value}");
    upsert_managed_key_line(lines, key, &replacement, npmrc_line_key, |line| {
        npmrc_line_value(line) == Some(value)
    });
}

fn npmrc_bool(input: &str, key: &str) -> Option<bool> {
    npmrc_value(input, key).and_then(|value| match value.to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    })
}

fn npmrc_u64(input: &str, key: &str) -> Option<u64> {
    npmrc_value(input, key).and_then(|value| value.parse::<u64>().ok())
}

fn npmrc_value(input: &str, key: &str) -> Option<String> {
    input.lines().find_map(|line| {
        if npmrc_line_key(line) == Some(key) {
            npmrc_line_value(line).map(ToOwned::to_owned)
        } else {
            None
        }
    })
}

fn npmrc_line_value(line: &str) -> Option<&str> {
    line.split_once('=').map(|(_, value)| {
        value
            .split_once('#')
            .map(|(before, _)| before)
            .unwrap_or(value)
            .trim()
    })
}

fn npmrc_line_key(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    line.split_once('=').map(|(key, _)| key.trim())
}

fn upsert_yaml_line(input: &str, key: &str, value: &str) -> String {
    let mut lines = input.lines().map(ToOwned::to_owned).collect::<Vec<_>>();
    let replacement = format!("{key}: {value}");
    upsert_managed_key_line(&mut lines, key, &replacement, yaml_line_key, |line| {
        yaml_line_value(line) == Some(value)
    });

    let mut output = lines.join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    output
}

fn upsert_pnpm_workspace_settings(input: &str) -> String {
    let mut lines = input.lines().map(ToOwned::to_owned).collect::<Vec<_>>();
    if !has_top_level_yaml_key(input, "packages") {
        lines.insert(0, MANAGED_MARKER.to_string());
        lines.insert(1, "packages:".to_string());
        lines.insert(2, PNPM_SINGLE_PACKAGE_ENTRY.to_string());
    }
    let workspace = finish_lines(lines);
    upsert_yaml_line(
        &workspace,
        MINIMUM_RELEASE_AGE_KEY,
        &PNPM_MIN_RELEASE_AGE_MINUTES.to_string(),
    )
}

fn has_top_level_yaml_key(input: &str, key: &str) -> bool {
    input.lines().any(|line| yaml_line_key(line) == Some(key))
}

fn remove_pnpm_workspace_settings(input: &str) -> String {
    let mut lines = input.lines().map(ToOwned::to_owned).collect::<Vec<_>>();
    remove_managed_yaml_blocks(&mut lines, "packages");
    remove_managed_key_lines(&mut lines, MINIMUM_RELEASE_AGE_KEY, yaml_line_key);
    trim_trailing_empty_lines(&mut lines);
    finish_lines(lines)
}

fn remove_yaml_line(input: &str, key: &str) -> String {
    let mut lines = input.lines().map(ToOwned::to_owned).collect::<Vec<_>>();
    remove_managed_key_lines(&mut lines, key, yaml_line_key);
    trim_trailing_empty_lines(&mut lines);
    finish_lines(lines)
}

fn yaml_line_key(line: &str) -> Option<&str> {
    if line_indent(line) > 0 {
        return None;
    }
    let line = line.trim_end();
    if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
        return None;
    }
    line.split_once(':').map(|(key, _)| key.trim())
}

fn yaml_line_value(line: &str) -> Option<&str> {
    line.split_once(':').map(|(_, value)| {
        value
            .split_once('#')
            .map(|(before, _)| before)
            .unwrap_or(value)
            .trim()
    })
}

fn upsert_bunfig_min_release_age(input: &str) -> Result<String> {
    if !input.trim().is_empty() {
        toml::from_str::<toml::Value>(input).context("parse existing bunfig.toml")?;
    }
    Ok(upsert_toml_table_integer(
        input,
        "install",
        "minimumReleaseAge",
        BUN_MIN_RELEASE_AGE_SECONDS,
    ))
}

fn upsert_toml_table_integer(input: &str, table: &str, key: &str, value: u64) -> String {
    let mut lines = input.lines().map(ToOwned::to_owned).collect::<Vec<_>>();
    let table_header = format!("[{table}]");
    let replacement = format!("{key} = {value}");

    if let Some(table_start) = lines
        .iter()
        .position(|line| line.trim() == table_header.as_str())
    {
        let table_end = lines
            .iter()
            .enumerate()
            .skip(table_start + 1)
            .find(|(_, line)| is_toml_table_header(line))
            .map(|(idx, _)| idx)
            .unwrap_or(lines.len());

        upsert_managed_key_line_in_range(
            &mut lines,
            table_start + 1,
            table_end,
            key,
            &replacement,
            toml_line_key,
            |line| toml_line_integer_value(line) == Some(value),
        );
    } else {
        if !lines.is_empty() && lines.last().is_some_and(|line| !line.trim().is_empty()) {
            lines.push(String::new());
        }
        lines.push(table_header);
        lines.push(MANAGED_MARKER.to_string());
        lines.push(replacement);
    }

    let mut output = lines.join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    output
}

fn remove_toml_table_key(input: &str, table: &str, key: &str) -> String {
    let mut lines = input.lines().map(ToOwned::to_owned).collect::<Vec<_>>();
    let table_header = format!("[{table}]");
    if let Some(table_start) = lines
        .iter()
        .position(|line| line.trim() == table_header.as_str())
    {
        let table_end = lines
            .iter()
            .enumerate()
            .skip(table_start + 1)
            .find(|(_, line)| is_toml_table_header(line))
            .map(|(idx, _)| idx)
            .unwrap_or(lines.len());
        remove_managed_key_lines_in_range(
            &mut lines,
            table_start + 1,
            table_end,
            key,
            toml_line_key,
        );
    }
    trim_trailing_empty_lines(&mut lines);
    finish_lines(lines)
}

fn upsert_managed_key_line(
    lines: &mut Vec<String>,
    key: &str,
    replacement: &str,
    key_fn: fn(&str) -> Option<&str>,
    desired_fn: impl Fn(&str) -> bool,
) {
    let end = lines.len();
    upsert_managed_key_line_in_range(lines, 0, end, key, replacement, key_fn, desired_fn);
}

fn upsert_managed_key_line_in_range(
    lines: &mut Vec<String>,
    start: usize,
    end: usize,
    key: &str,
    replacement: &str,
    key_fn: fn(&str) -> Option<&str>,
    desired_fn: impl Fn(&str) -> bool,
) {
    if let Some(offset) = lines[start..end]
        .iter()
        .position(|line| key_fn(line) == Some(key))
    {
        let idx = start + offset;
        if desired_fn(&lines[idx]) && !is_managed_previous_line(lines, idx) {
            return;
        }
        lines[idx] = replacement.to_string();
        if !is_managed_previous_line(lines, idx) {
            lines.insert(idx, MANAGED_MARKER.to_string());
        }
    } else {
        lines.insert(end, MANAGED_MARKER.to_string());
        lines.insert(end + 1, replacement.to_string());
    }
}

fn remove_managed_key_lines(lines: &mut Vec<String>, key: &str, key_fn: fn(&str) -> Option<&str>) {
    let end = lines.len();
    remove_managed_key_lines_in_range(lines, 0, end, key, key_fn);
}

fn remove_managed_yaml_blocks(lines: &mut Vec<String>, key: &str) {
    let mut idx = 0;
    while idx < lines.len() {
        if yaml_line_key(&lines[idx]) == Some(key) && is_managed_previous_line(lines, idx) {
            let mut block_end = idx + 1;
            while block_end < lines.len() && line_indent(&lines[block_end]) > 0 {
                block_end += 1;
            }
            lines.drain((idx - 1)..block_end);
            idx = idx.saturating_sub(1);
        } else {
            idx += 1;
        }
    }
}

fn remove_managed_key_lines_in_range(
    lines: &mut Vec<String>,
    start: usize,
    end: usize,
    key: &str,
    key_fn: fn(&str) -> Option<&str>,
) {
    let mut idx = start;
    let mut end = end.min(lines.len());
    while idx < end {
        if key_fn(&lines[idx]) == Some(key) && is_managed_previous_line(lines, idx) {
            lines.remove(idx);
            lines.remove(idx - 1);
            end = end.saturating_sub(2);
            idx = idx.saturating_sub(1);
        } else {
            idx += 1;
        }
    }
}

fn is_managed_previous_line(lines: &[String], idx: usize) -> bool {
    idx > 0 && lines[idx - 1].trim() == MANAGED_MARKER
}

fn trim_trailing_empty_lines(lines: &mut Vec<String>) {
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
}

fn finish_lines(lines: Vec<String>) -> String {
    let mut output = lines.join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    output
}

fn is_toml_table_header(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with('[') && trimmed.ends_with(']')
}

fn toml_line_key(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    line.split_once('=').map(|(key, _)| key.trim())
}

fn toml_line_integer_value(line: &str) -> Option<u64> {
    line.split_once('=').and_then(|(_, value)| {
        value
            .split_once('#')
            .map_or(value, |(before, _)| before)
            .trim()
            .parse()
            .ok()
    })
}

fn find_package_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let walk = package_dir_walk(root);

    for entry in walk.build().flatten() {
        if let Some(package_dir) = package_dir_from_walk_entry(root, &entry) {
            out.push(package_dir);
        }
    }

    out.sort();
    out
}

fn package_dir_walk(root: &Path) -> WalkBuilder {
    let mut walk = WalkBuilder::new(root);
    walk.standard_filters(true);
    walk.hidden(false);
    walk.require_git(false);
    walk.follow_links(false);
    walk.filter_entry(|entry| !is_skipped_package_walk_dir(entry.file_name()));
    walk
}

fn package_dir_from_walk_entry(root: &Path, entry: &ignore::DirEntry) -> Option<PathBuf> {
    if !entry
        .file_type()
        .is_some_and(|file_type| file_type.is_dir())
    {
        return None;
    }
    let path = entry.path();
    if !path.join(PACKAGE_JSON).is_file() {
        return None;
    }
    Some(relative_package_dir(root, path))
}

fn relative_package_dir(root: &Path, path: &Path) -> PathBuf {
    let rel = path
        .strip_prefix(root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| path.to_path_buf());
    if rel.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        rel
    }
}

fn detect_package_managers(root: &Path, package_dirs: &[PathBuf]) -> Vec<PackageManager> {
    let mut managers = Vec::new();
    for package_dir in package_dirs {
        let dir = if package_dir == Path::new(".") {
            root.to_path_buf()
        } else {
            root.join(package_dir)
        };
        if let Some(manager) = package_manager_from_package_json(&dir.join(PACKAGE_JSON)) {
            managers.push(manager);
        }
    }

    if root.join("pnpm-lock.yaml").is_file() || root.join(PNPM_WORKSPACE_FILE).is_file() {
        managers.push(PackageManager::Pnpm);
    }
    if root.join("yarn.lock").is_file() || root.join(YARNRC_FILE).is_file() {
        managers.push(PackageManager::Yarn);
    }
    if root.join("bun.lock").is_file()
        || root.join("bun.lockb").is_file()
        || root.join(BUNFIG_FILE).is_file()
    {
        managers.push(PackageManager::Bun);
    }
    if root.join("package-lock.json").is_file() || root.join("npm-shrinkwrap.json").is_file() {
        managers.push(PackageManager::Npm);
    }

    if managers.is_empty() && !package_dirs.is_empty() {
        managers.push(PackageManager::Npm);
    }

    managers.sort();
    managers.dedup();
    managers
}

fn package_manager_from_package_json(path: &Path) -> Option<PackageManager> {
    let text = fs::read_to_string(path).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    let package_manager = value.get("packageManager")?.as_str()?;
    let name = package_manager.split('@').next().unwrap_or(package_manager);
    match name {
        "npm" => Some(PackageManager::Npm),
        "pnpm" => Some(PackageManager::Pnpm),
        "yarn" => Some(PackageManager::Yarn),
        "bun" => Some(PackageManager::Bun),
        _ => None,
    }
}

fn resolve_pnpm_workspace_path(root: &Path, package_dirs: &[PathBuf]) -> PathBuf {
    let root_workspace = root.join(PNPM_WORKSPACE_FILE);
    if root_workspace.is_file() {
        return root_workspace;
    }

    package_dirs
        .iter()
        .map(|package_dir| package_dir_to_abs(root, package_dir))
        .find(|dir| dir.join(PNPM_WORKSPACE_FILE).is_file())
        .map(|dir| dir.join(PNPM_WORKSPACE_FILE))
        .or_else(|| {
            package_dirs
                .iter()
                .map(|package_dir| package_dir_to_abs(root, package_dir))
                .find(|dir| {
                    package_manager_from_package_json(&dir.join(PACKAGE_JSON))
                        == Some(PackageManager::Pnpm)
                })
                .map(|dir| dir.join(PNPM_WORKSPACE_FILE))
        })
        .unwrap_or(root_workspace)
}

fn resolve_npmrc_path(root: &Path, package_dirs: &[PathBuf]) -> PathBuf {
    let root_npmrc = root.join(NPMRC_FILE);
    if is_root_package_project(root, package_dirs) || root_npmrc.is_file() {
        // Preserve an existing root-level npm config instead of moving user-owned settings.
        return root_npmrc;
    }

    if let Some(existing_npmrc) = package_dirs
        .iter()
        .map(|package_dir| package_dir_to_abs(root, package_dir))
        .map(|dir| dir.join(NPMRC_FILE))
        .find(|path| path.is_file())
    {
        return existing_npmrc;
    }

    package_dirs
        .iter()
        .find(|package_dir| package_dir_uses_npmrc(root, package_dir))
        .or_else(|| package_dirs.first())
        .map(|dir| package_dir_to_abs(root, dir).join(NPMRC_FILE))
        .unwrap_or(root_npmrc)
}

fn package_dir_uses_npmrc(root: &Path, package_dir: &Path) -> bool {
    matches!(
        package_manager_from_package_json(
            &package_dir_to_abs(root, package_dir).join(PACKAGE_JSON)
        ),
        Some(PackageManager::Npm | PackageManager::Pnpm)
    )
}

fn package_dir_to_abs(root: &Path, package_dir: &Path) -> PathBuf {
    if package_dir == Path::new(".") {
        root.to_path_buf()
    } else {
        root.join(package_dir)
    }
}

fn bun_min_release_age_seconds(path: &Path) -> Option<u64> {
    let text = fs::read_to_string(path).ok()?;
    let value = toml::from_str::<toml::Value>(&text).ok()?;
    value
        .get("install")
        .and_then(|install| install.get("minimumReleaseAge"))
        .and_then(toml::Value::as_integer)
        .and_then(|value| u64::try_from(value).ok())
}

fn has_lockfile_for_package_dir(root: &Path, package_dir: &Path) -> bool {
    let dir = package_dir_to_abs(root, package_dir);
    has_lockfile(&dir) || has_lockfile(root)
}

fn has_lockfile(dir: &Path) -> bool {
    PACKAGE_LOCK_FILES
        .iter()
        .any(|name| dir.join(name).is_file())
}

fn is_skipped_package_walk_dir(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| PACKAGE_WALK_SKIP_DIRS.contains(&name))
}

fn dependabot_status(root: &Path) -> DependencyBotStatus {
    for rel in DEPENDABOT_FILES {
        let path = root.join(rel);
        if !path.is_file() {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        let (configured, cooldown_ok, cooldown_days) = dependabot_cooldown_status(&text);
        return DependencyBotStatus {
            config_path: Some(PathBuf::from(rel)),
            configured,
            cooldown_ok,
            cooldown_days,
        };
    }
    DependencyBotStatus {
        config_path: None,
        configured: false,
        cooldown_ok: false,
        cooldown_days: None,
    }
}

fn dependabot_cooldown_status(text: &str) -> (bool, bool, Option<u64>) {
    let blocks = dependabot_npm_update_blocks(text);
    if blocks.is_empty() {
        return (false, false, None);
    }

    let days = blocks
        .iter()
        .filter_map(|block| dependabot_block_cooldown_days(block))
        .min();
    let cooldown_ok = days
        .map(|value| value >= MIN_RELEASE_AGE_DAYS)
        .unwrap_or(false);
    (true, cooldown_ok, days)
}

fn dependabot_npm_update_blocks(text: &str) -> Vec<String> {
    let lines = text.lines().collect::<Vec<_>>();
    let mut blocks = Vec::new();
    let mut idx = 0;
    while idx < lines.len() {
        let line = lines[idx];
        if !line_contains_package_ecosystem(line, "npm") {
            idx += 1;
            continue;
        }

        let start_indent = line_indent(line);
        let mut end = idx + 1;
        while end < lines.len() {
            let next = lines[end];
            if line_contains_package_ecosystem(next, "npm")
                || line_contains_package_ecosystem(next, "yarn")
                || (next.trim_start().starts_with("- ")
                    && line_indent(next) <= start_indent
                    && next.contains("package-ecosystem"))
            {
                break;
            }
            end += 1;
        }
        blocks.push(lines[idx..end].join("\n"));
        idx = end;
    }
    blocks
}

fn line_contains_package_ecosystem(line: &str, ecosystem: &str) -> bool {
    let trimmed = line.trim();
    let Some((key, value)) = trimmed.split_once(':') else {
        return false;
    };
    key.trim_start_matches("- ").trim() == "package-ecosystem" && unquote(value.trim()) == ecosystem
}

fn dependabot_block_cooldown_days(block: &str) -> Option<u64> {
    if !block.lines().any(|line| line.trim() == "cooldown:") {
        return None;
    }

    [
        "default-days",
        "semver-major-days",
        "semver-minor-days",
        "semver-patch-days",
    ]
    .iter()
    .filter_map(|key| yaml_u64(block, key))
    .min()
}

fn yaml_u64(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let trimmed = line.trim();
        let (line_key, value) = trimmed.split_once(':')?;
        (line_key == key).then(|| unquote(value.trim()).parse::<u64>().ok())?
    })
}

fn yaml_top_level_u64(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (line_key, value) = yaml_line_key(line).zip(line.split_once(':').map(|(_, v)| v))?;
        (line_key == key).then(|| unquote(value.trim()).parse::<u64>().ok())?
    })
}

fn line_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn unquote(value: &str) -> &str {
    let value = value.trim_matches('"').trim_matches('\'');
    value
        .split_once('#')
        .map(|(before, _)| before.trim())
        .unwrap_or(value)
}

fn renovate_status(root: &Path) -> DependencyBotStatus {
    if let Some(package_json) = package_json_renovate_status(root) {
        return package_json;
    }

    for rel in RENOVATE_FILES {
        let path = root.join(rel);
        if !path.is_file() {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        let days = renovate_minimum_release_age_days(&text);
        return DependencyBotStatus {
            config_path: Some(PathBuf::from(rel)),
            configured: true,
            cooldown_ok: days
                .map(|value| value >= MIN_RELEASE_AGE_DAYS)
                .unwrap_or(false),
            cooldown_days: days,
        };
    }

    DependencyBotStatus {
        config_path: None,
        configured: false,
        cooldown_ok: false,
        cooldown_days: None,
    }
}

fn package_json_renovate_status(root: &Path) -> Option<DependencyBotStatus> {
    let path = root.join(PACKAGE_JSON);
    let text = fs::read_to_string(path).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    let renovate = value.get("renovate")?;
    let days = renovate_minimum_release_age_days(&renovate.to_string());
    Some(DependencyBotStatus {
        config_path: Some(PathBuf::from(PACKAGE_JSON)),
        configured: true,
        cooldown_ok: days
            .map(|value| value >= MIN_RELEASE_AGE_DAYS)
            .unwrap_or(false),
        cooldown_days: days,
    })
}

fn renovate_minimum_release_age_days(text: &str) -> Option<u64> {
    let value = serde_json::from_str::<serde_json::Value>(text).ok();
    if let Some(value) = value
        && let Some(days) = find_minimum_release_age_days_in_json(&value)
    {
        return Some(days);
    }
    minimum_release_age_days_from_text(text)
}

fn find_minimum_release_age_days_in_json(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Object(map) => map.iter().find_map(|(key, value)| {
            if key == "minimumReleaseAge" {
                value
                    .as_str()
                    .and_then(parse_duration_days)
                    .or_else(|| value.as_u64())
            } else {
                find_minimum_release_age_days_in_json(value)
            }
        }),
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(find_minimum_release_age_days_in_json),
        _ => None,
    }
}

fn minimum_release_age_days_from_text(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        if !line.contains("minimumReleaseAge") {
            return None;
        }
        let (_, value) = line.split_once(':')?;
        parse_duration_days(unquote(value.trim().trim_end_matches(',')))
    })
}

fn parse_duration_days(value: &str) -> Option<u64> {
    let value = value.trim();
    let number = value
        .split_whitespace()
        .next()
        .unwrap_or(value)
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches('d')
        .parse::<u64>()
        .ok()?;
    Some(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upserts_missing_and_insecure_npmrc_settings() {
        let out = upsert_npmrc_settings(
            r#"# keep
ignore-scripts=false
min-release-age=1
"#,
            &[PackageManager::Npm],
        );
        assert!(out.contains("# keep\n"), "{out}");
        assert!(out.contains("ignore-scripts=true\n"), "{out}");
        assert!(out.contains("min-release-age=7\n"), "{out}");
        assert_eq!(out.matches("ignore-scripts=").count(), 1);
        assert_eq!(out.matches("min-release-age=").count(), 1);
    }

    #[test]
    fn skips_package_json_under_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
        fs::write(dir.path().join("node_modules/pkg/package.json"), "{}").unwrap();
        assert!(find_package_dirs(dir.path()).is_empty());
    }

    #[test]
    fn detects_root_package_json() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(PACKAGE_JSON), "{}").unwrap();
        assert_eq!(find_package_dirs(dir.path()), vec![PathBuf::from(".")]);
    }

    #[test]
    fn skips_package_json_under_gitignored_dirs() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "cache/\n").unwrap();
        fs::create_dir_all(dir.path().join("cache/pkg")).unwrap();
        fs::write(dir.path().join("cache/pkg/package.json"), "{}").unwrap();
        assert!(find_package_dirs(dir.path()).is_empty());
    }

    #[test]
    fn detects_package_json_under_hidden_dirs() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".next/server")).unwrap();
        fs::write(dir.path().join(".next/server/package.json"), "{}").unwrap();
        assert_eq!(
            find_package_dirs(dir.path()),
            vec![PathBuf::from(".next/server")]
        );
    }

    #[test]
    fn detects_missing_lockfiles_per_package_dir() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("packages/web")).unwrap();
        fs::write(dir.path().join("packages/web/package.json"), "{}").unwrap();
        let initial_status = status(dir.path());
        assert_eq!(
            initial_status.package_dirs_without_lockfile,
            vec![PathBuf::from("packages/web")]
        );
        fs::write(dir.path().join("package-lock.json"), "{}").unwrap();
        assert!(status(dir.path()).package_dirs_without_lockfile.is_empty());
    }

    #[test]
    fn detects_dependabot_npm_cooldown() {
        let text = r#"
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    cooldown:
      default-days: 7
"#;
        assert_eq!(dependabot_cooldown_status(text), (true, true, Some(7)));
    }

    #[test]
    fn detects_renovate_minimum_release_age() {
        let text = r#"{"packageRules":[{"matchManagers":["npm"],"minimumReleaseAge":"7 days"}]}"#;
        assert_eq!(renovate_minimum_release_age_days(text), Some(7));
    }

    #[test]
    fn applies_package_manager_specific_age_gates() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(PACKAGE_JSON),
            r#"{"packageManager":"pnpm@10.0.0"}"#,
        )
        .unwrap();
        apply(dir.path()).unwrap();
        let npmrc = fs::read_to_string(dir.path().join(NPMRC_FILE)).unwrap();
        assert!(npmrc.contains("ignore-scripts=true"), "{npmrc}");
        assert!(!npmrc.contains("min-release-age=7"), "{npmrc}");
        let pnpm_workspace = fs::read_to_string(dir.path().join(PNPM_WORKSPACE_FILE)).unwrap();
        assert!(
            pnpm_workspace.contains("packages:\n  - \".\"\n"),
            "{pnpm_workspace}"
        );
        assert!(
            pnpm_workspace.contains("minimumReleaseAge: 10080"),
            "{pnpm_workspace}"
        );

        fs::write(
            dir.path().join(PACKAGE_JSON),
            r#"{"packageManager":"yarn@4.0.0"}"#,
        )
        .unwrap();
        apply(dir.path()).unwrap();
        let yarnrc = fs::read_to_string(dir.path().join(YARNRC_FILE)).unwrap();
        assert!(yarnrc.contains("npmMinimalAgeGate: 10080"), "{yarnrc}");
        assert_eq!(
            status(dir.path()).yarn_min_release_age_minutes,
            Some(YARN_MIN_RELEASE_AGE_MINUTES)
        );

        fs::write(
            dir.path().join(PACKAGE_JSON),
            r#"{"packageManager":"bun@1.2.0"}"#,
        )
        .unwrap();
        apply(dir.path()).unwrap();
        let bunfig = fs::read_to_string(dir.path().join(BUNFIG_FILE)).unwrap();
        assert!(bunfig.contains("minimumReleaseAge = 604800"), "{bunfig}");
    }

    #[test]
    fn applies_pnpm_workspace_age_gate_in_nested_project() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("apps/web");
        fs::create_dir_all(&app).unwrap();
        fs::write(
            app.join(PACKAGE_JSON),
            r#"{"name":"web","packageManager":"pnpm@11.0.0"}"#,
        )
        .unwrap();
        fs::write(
            app.join(PNPM_WORKSPACE_FILE),
            "onlyBuiltDependencies:\n  - esbuild\n",
        )
        .unwrap();

        apply(dir.path()).unwrap();

        assert!(!dir.path().join(NPMRC_FILE).exists());
        let npmrc = fs::read_to_string(app.join(NPMRC_FILE)).unwrap();
        assert!(npmrc.contains("ignore-scripts=true"), "{npmrc}");
        let root_workspace = dir.path().join(PNPM_WORKSPACE_FILE);
        assert!(!root_workspace.exists());
        let pnpm_workspace = fs::read_to_string(app.join(PNPM_WORKSPACE_FILE)).unwrap();
        assert!(
            pnpm_workspace.contains("minimumReleaseAge: 10080"),
            "{pnpm_workspace}"
        );
    }

    #[test]
    fn resolves_npmrc_to_nested_package_project() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("apps/web");
        fs::create_dir_all(&app).unwrap();
        fs::write(
            app.join(PACKAGE_JSON),
            r#"{"name":"web","packageManager":"pnpm@11.0.0"}"#,
        )
        .unwrap();

        let status = status(dir.path());

        assert_eq!(status.npmrc_path, app.join(NPMRC_FILE));
    }

    #[test]
    fn resolves_new_npmrc_to_nested_npmrc_package_manager() {
        let dir = tempfile::tempdir().unwrap();
        let yarn_app = dir.path().join("apps/a-yarn");
        let pnpm_app = dir.path().join("apps/z-pnpm");
        fs::create_dir_all(&yarn_app).unwrap();
        fs::create_dir_all(&pnpm_app).unwrap();
        fs::write(
            yarn_app.join(PACKAGE_JSON),
            r#"{"name":"a-yarn","packageManager":"yarn@4.0.0"}"#,
        )
        .unwrap();
        fs::write(
            pnpm_app.join(PACKAGE_JSON),
            r#"{"name":"z-pnpm","packageManager":"pnpm@11.0.0"}"#,
        )
        .unwrap();

        let status = status(dir.path());

        assert_eq!(status.npmrc_path, pnpm_app.join(NPMRC_FILE));
    }

    #[test]
    fn preserves_existing_root_npmrc_for_nested_package_project() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("apps/web");
        fs::create_dir_all(&app).unwrap();
        fs::write(
            app.join(PACKAGE_JSON),
            r#"{"name":"web","packageManager":"pnpm@11.0.0"}"#,
        )
        .unwrap();
        fs::write(dir.path().join(NPMRC_FILE), "ignore-scripts=false\n").unwrap();

        let status = status(dir.path());

        assert_eq!(status.npmrc_path, dir.path().join(NPMRC_FILE));
    }

    #[test]
    fn updates_existing_nested_npmrc_without_root_project() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("apps/web");
        fs::create_dir_all(&app).unwrap();
        fs::write(
            app.join(PACKAGE_JSON),
            r#"{"name":"web","packageManager":"npm@10.0.0"}"#,
        )
        .unwrap();
        fs::write(
            app.join(NPMRC_FILE),
            "registry=https://registry.npmjs.org/\nignore-scripts=false\nmin-release-age=1\n",
        )
        .unwrap();

        apply(dir.path()).unwrap();

        assert!(!dir.path().join(NPMRC_FILE).exists());
        let npmrc = fs::read_to_string(app.join(NPMRC_FILE)).unwrap();
        assert!(
            npmrc.contains("registry=https://registry.npmjs.org/"),
            "{npmrc}"
        );
        assert!(npmrc.contains("ignore-scripts=true\n"), "{npmrc}");
        assert!(npmrc.contains("min-release-age=7\n"), "{npmrc}");
        assert_eq!(npmrc.matches("ignore-scripts=").count(), 1, "{npmrc}");
        assert_eq!(npmrc.matches("min-release-age=").count(), 1, "{npmrc}");
    }

    #[test]
    fn nested_pnpm_workspace_wins_when_root_has_package_json() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(PACKAGE_JSON),
            r#"{"name":"root","packageManager":"npm@10.0.0"}"#,
        )
        .unwrap();
        let app = dir.path().join("apps/web");
        fs::create_dir_all(&app).unwrap();
        fs::write(
            app.join(PACKAGE_JSON),
            r#"{"name":"web","packageManager":"pnpm@11.0.0"}"#,
        )
        .unwrap();
        fs::write(app.join(PNPM_WORKSPACE_FILE), "packages: []\n").unwrap();

        apply(dir.path()).unwrap();

        assert!(!dir.path().join(PNPM_WORKSPACE_FILE).exists());
        let nested = fs::read_to_string(app.join(PNPM_WORKSPACE_FILE)).unwrap();
        assert!(nested.contains("minimumReleaseAge: 10080"), "{nested}");
    }

    #[test]
    fn unapply_removes_supported_hardening_settings() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(PACKAGE_JSON),
            r#"{"packageManager":"pnpm@11.0.0"}"#,
        )
        .unwrap();
        apply(dir.path()).unwrap();
        assert!(status(dir.path()).package_scripts_ok());
        assert!(status(dir.path()).age_gates_ok());

        unapply(dir.path()).unwrap();

        let npmrc = fs::read_to_string(dir.path().join(NPMRC_FILE)).unwrap_or_default();
        assert!(!npmrc.contains("ignore-scripts=true"), "{npmrc}");
        assert!(!dir.path().join(PNPM_WORKSPACE_FILE).exists());
        assert!(!status(dir.path()).package_scripts_ok());
        assert!(!status(dir.path()).age_gates_ok());
    }

    #[test]
    fn unapply_preserves_user_owned_matching_settings() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(PACKAGE_JSON),
            r#"{"packageManager":"npm@10.0.0"}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join(NPMRC_FILE),
            "ignore-scripts=true\nmin-release-age=7\n",
        )
        .unwrap();

        apply(dir.path()).unwrap();
        unapply(dir.path()).unwrap();

        let npmrc = fs::read_to_string(dir.path().join(NPMRC_FILE)).unwrap();
        assert!(npmrc.contains("ignore-scripts=true"), "{npmrc}");
        assert!(npmrc.contains("min-release-age=7"), "{npmrc}");
        assert!(!npmrc.contains(MANAGED_MARKER), "{npmrc}");
    }

    #[test]
    fn bunfig_update_preserves_valid_existing_content() {
        let input = "# keep\ntelemetry = false\n\n[install]\ncache = true\n";
        let out = upsert_bunfig_min_release_age(input).unwrap();
        assert!(out.contains("# keep\n"), "{out}");
        assert!(out.contains("telemetry = false\n"), "{out}");
        assert!(out.contains("[install]\ncache = true\n"), "{out}");
        assert!(out.contains("minimumReleaseAge = 604800\n"), "{out}");
    }

    #[test]
    fn bunfig_update_rejects_invalid_toml_without_replacing_content() {
        let err = upsert_bunfig_min_release_age("[install\nbroken = true\n").unwrap_err();
        assert!(
            err.to_string().contains("parse existing bunfig.toml"),
            "{err}"
        );
    }

    #[test]
    fn yaml_upsert_only_updates_top_level_keys() {
        let out = upsert_yaml_line(
            "nested:\n  minimumReleaseAge: 1\n",
            MINIMUM_RELEASE_AGE_KEY,
            "10080",
        );
        assert!(out.contains("  minimumReleaseAge: 1\n"), "{out}");
        assert!(out.contains("minimumReleaseAge: 10080\n"), "{out}");
    }

    #[test]
    fn pnpm_workspace_upsert_adds_single_package_for_new_file() {
        let out = upsert_pnpm_workspace_settings("");
        assert_eq!(
            out,
            "# shk-managed npm-hardening\npackages:\n  - \".\"\n# shk-managed npm-hardening\nminimumReleaseAge: 10080\n"
        );
    }

    #[test]
    fn pnpm_workspace_upsert_preserves_existing_packages() {
        let out = upsert_pnpm_workspace_settings("packages:\n  - \"apps/*\"\n");
        assert!(out.contains("  - \"apps/*\"\n"), "{out}");
        assert!(!out.contains("  - \".\"\n"), "{out}");
        assert!(out.contains("minimumReleaseAge: 10080\n"), "{out}");
    }

    #[test]
    fn pnpm_workspace_upsert_updates_existing_age_gate_without_touching_packages() {
        let out = upsert_pnpm_workspace_settings(
            "packages:\n  - \"apps/*\"\n# shk-managed npm-hardening\nminimumReleaseAge: 1\n",
        );
        assert_eq!(
            out,
            "packages:\n  - \"apps/*\"\n# shk-managed npm-hardening\nminimumReleaseAge: 10080\n"
        );
    }

    #[test]
    fn pnpm_workspace_upsert_repairs_existing_file_without_packages() {
        let out =
            upsert_pnpm_workspace_settings("# shk-managed npm-hardening\nminimumReleaseAge: 1\n");
        assert_eq!(
            out,
            "# shk-managed npm-hardening\npackages:\n  - \".\"\n# shk-managed npm-hardening\nminimumReleaseAge: 10080\n"
        );
    }

    #[test]
    fn pnpm_workspace_upsert_handles_comment_only_file() {
        let out = upsert_pnpm_workspace_settings("# keep this comment\n");
        assert_eq!(
            out,
            "# shk-managed npm-hardening\npackages:\n  - \".\"\n# keep this comment\n# shk-managed npm-hardening\nminimumReleaseAge: 10080\n"
        );
    }

    #[test]
    fn pnpm_workspace_unapply_removes_managed_single_package_block() {
        let out = remove_pnpm_workspace_settings(
            "# shk-managed npm-hardening\npackages:\n  - \".\"\n# shk-managed npm-hardening\nminimumReleaseAge: 10080\n",
        );
        assert_eq!(out, "");
    }

    #[test]
    fn pnpm_workspace_unapply_preserves_user_owned_packages() {
        let out = remove_pnpm_workspace_settings(
            "packages:\n  - \".\"\n# shk-managed npm-hardening\nminimumReleaseAge: 10080\n",
        );
        assert_eq!(out, "packages:\n  - \".\"\n");
    }
}
