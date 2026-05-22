use anyhow::{Context, Result};
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
    let npmrc_path = root.join(NPMRC_FILE);
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
            fs::write(&before.npmrc_path, updated)?;
        }
    }
    if before.package_managers.contains(&PackageManager::Pnpm) {
        let existing = fs::read_to_string(&before.pnpm_workspace_path).unwrap_or_default();
        let updated = upsert_yaml_line(
            &existing,
            MINIMUM_RELEASE_AGE_KEY,
            &PNPM_MIN_RELEASE_AGE_MINUTES.to_string(),
        );
        if updated != existing {
            fs::write(&before.pnpm_workspace_path, updated)?;
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
            fs::write(&before.yarnrc_path, updated)?;
        }
    }
    if before.package_managers.contains(&PackageManager::Bun) {
        let existing = fs::read_to_string(&before.bunfig_path).unwrap_or_default();
        let updated = upsert_bunfig_min_release_age(&existing)
            .with_context(|| format!("update {}", before.bunfig_path.display()))?;
        if updated != existing {
            fs::write(&before.bunfig_path, updated)?;
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
            fs::write(&before.npmrc_path, updated)?;
        }
    }
    if before.package_managers.contains(&PackageManager::Pnpm) {
        let existing = fs::read_to_string(&before.pnpm_workspace_path).unwrap_or_default();
        let updated = remove_yaml_line(&existing, MINIMUM_RELEASE_AGE_KEY);
        if updated != existing {
            fs::write(&before.pnpm_workspace_path, updated)?;
        }
    }
    if before.package_managers.contains(&PackageManager::Yarn) {
        let existing = fs::read_to_string(&before.yarnrc_path).unwrap_or_default();
        let updated = remove_yaml_line(&existing, YARN_MIN_RELEASE_AGE_KEY);
        if updated != existing {
            fs::write(&before.yarnrc_path, updated)?;
        }
    }
    if before.package_managers.contains(&PackageManager::Bun) {
        let existing = fs::read_to_string(&before.bunfig_path).unwrap_or_default();
        let updated = remove_toml_table_key(&existing, "install", "minimumReleaseAge");
        if updated != existing {
            fs::write(&before.bunfig_path, updated)?;
        }
    }

    Ok(Some(status(root)))
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
    let mut remove_keys = vec![IGNORE_SCRIPTS_KEY];
    if package_managers.contains(&PackageManager::Npm) {
        remove_keys.push(MIN_RELEASE_AGE_KEY);
    }
    let mut lines = input
        .lines()
        .filter(|line| {
            npmrc_line_key(line)
                .map(|key| !remove_keys.contains(&key))
                .unwrap_or(true)
        })
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    trim_trailing_empty_lines(&mut lines);
    finish_lines(lines)
}

fn upsert_npmrc_line(lines: &mut Vec<String>, key: &str, value: &str) {
    let replacement = format!("{key}={value}");
    if let Some(line) = lines
        .iter_mut()
        .find(|line| npmrc_line_key(line) == Some(key))
    {
        *line = replacement;
    } else {
        lines.push(replacement);
    }
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
            line.split_once('=').map(|(_, value)| {
                value
                    .split_once('#')
                    .map(|(before, _)| before)
                    .unwrap_or(value)
                    .trim()
                    .to_string()
            })
        } else {
            None
        }
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
    if let Some(line) = lines
        .iter_mut()
        .find(|line| yaml_line_key(line) == Some(key))
    {
        *line = replacement;
    } else {
        lines.push(replacement);
    }

    let mut output = lines.join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    output
}

fn remove_yaml_line(input: &str, key: &str) -> String {
    let mut lines = input
        .lines()
        .filter(|line| yaml_line_key(line) != Some(key))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
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

        if let Some(line) = lines[table_start + 1..table_end]
            .iter_mut()
            .find(|line| toml_line_key(line) == Some(key))
        {
            *line = replacement;
        } else {
            lines.insert(table_end, replacement);
        }
    } else {
        if !lines.is_empty() && lines.last().is_some_and(|line| !line.trim().is_empty()) {
            lines.push(String::new());
        }
        lines.push(table_header);
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
        if let Some(offset) = lines[table_start + 1..table_end]
            .iter()
            .position(|line| toml_line_key(line) == Some(key))
        {
            lines.remove(table_start + 1 + offset);
        }
    }
    trim_trailing_empty_lines(&mut lines);
    finish_lines(lines)
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

fn find_package_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    visit_package_dirs(root, root, &mut out);
    out.sort();
    out
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
    if root_workspace.is_file() || root.join(PACKAGE_JSON).is_file() {
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

fn visit_package_dirs(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    if dir.join(PACKAGE_JSON).is_file() {
        let rel = dir
            .strip_prefix(root)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| dir.to_path_buf());
        out.push(if rel.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            rel
        });
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if is_skipped_dir(&name) {
            continue;
        }
        visit_package_dirs(root, &entry.path(), out);
    }
}

fn is_skipped_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "node_modules" | "dist" | "build" | "coverage" | "target"
    )
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

        let root_workspace = dir.path().join(PNPM_WORKSPACE_FILE);
        assert!(!root_workspace.exists());
        let pnpm_workspace = fs::read_to_string(app.join(PNPM_WORKSPACE_FILE)).unwrap();
        assert!(
            pnpm_workspace.contains("minimumReleaseAge: 10080"),
            "{pnpm_workspace}"
        );
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
        let pnpm_workspace =
            fs::read_to_string(dir.path().join(PNPM_WORKSPACE_FILE)).unwrap_or_default();
        assert!(!npmrc.contains("ignore-scripts=true"), "{npmrc}");
        assert!(
            !pnpm_workspace.contains("minimumReleaseAge"),
            "{pnpm_workspace}"
        );
        assert!(!status(dir.path()).package_scripts_ok());
        assert!(!status(dir.path()).age_gates_ok());
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
}
