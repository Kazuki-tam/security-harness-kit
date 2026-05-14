use crate::custom_rules;
use crate::finding::{Finding, ScanJsonReport, ScanSummary};
use crate::git;
use crate::policy::{ColorMode, Policy, Severity};
use crate::suppression;
use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub struct ScanOptions {
    pub staged: bool,
    pub git_history: bool,
    pub git_history_ref: Option<String>,
    pub git_history_since: Option<String>,
    pub git_history_max_commits: Option<usize>,
    pub json: bool,
    pub fail_on_override: Option<Severity>,
    pub use_pre_commit_threshold: bool,
    pub include_context: bool,
    pub include_binary: bool,
    pub follow_symlinks: bool,
}

pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub scanned_paths: Vec<String>,
    pub policy: Policy,
    pub policy_path: Option<PathBuf>,
    pub exit_threshold: Severity,
    pub suppressed: u64,
    pub deduplicated: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct GitHistoryPreview {
    pub version: u32,
    pub mode: String,
    pub scope: String,
    pub since: Option<String>,
    pub max_commits: Option<usize>,
    pub candidate_commits: usize,
    pub candidate_paths: usize,
    pub unique_blobs: usize,
    pub policy_filtered_blobs: usize,
    pub sample_paths: Vec<String>,
    pub policy_path: Option<String>,
}

impl ScanResult {
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings
            .iter()
            .filter_map(|f| Severity::parse(&f.severity))
            .max()
    }

    pub fn should_fail(&self) -> bool {
        let threshold = self.exit_threshold;
        self.findings.iter().any(|f| {
            Severity::parse(&f.severity)
                .map(|s| s.meets_threshold(threshold))
                .unwrap_or(false)
        })
    }

    pub fn to_json_report(&self, color_mode: ColorMode) -> ScanJsonReport {
        let mut by_sev: BTreeMap<String, usize> = BTreeMap::new();
        for f in &self.findings {
            *by_sev.entry(f.severity.clone()).or_insert(0) += 1;
        }
        ScanJsonReport {
            version: 1,
            scanned_paths: self.scanned_paths.clone(),
            findings: self.findings.clone(),
            summary: ScanSummary {
                total: self.findings.len(),
                by_severity: by_sev,
            },
            exit_threshold: self.exit_threshold.as_str().to_string(),
            policy_path: self.policy_path.as_ref().map(|p| p.display().to_string()),
            suppressed: self.suppressed,
            deduplicated: self.deduplicated,
            color_mode: match color_mode {
                ColorMode::Auto => "auto".into(),
                ColorMode::Always => "always".into(),
                ColorMode::Never => "never".into(),
            },
        }
    }
}

fn git_history_options(opts: &ScanOptions) -> git::GitHistoryOptions {
    git::GitHistoryOptions {
        rev: opts.git_history_ref.clone(),
        since: opts.git_history_since.clone(),
        max_commits: opts.git_history_max_commits,
    }
}

struct GitHistorySelection {
    repo: PathBuf,
    policy: Policy,
    policy_path: Option<PathBuf>,
    history_opts: git::GitHistoryOptions,
    candidate_commits: usize,
    candidate_paths: usize,
    unique_blobs: usize,
    filtered_blobs: Vec<git::GitHistoryBlob>,
}

fn is_probably_binary(head: &[u8]) -> bool {
    head.contains(&0)
}

fn build_exclude_set(patterns: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let g = Glob::new(p).with_context(|| format!("invalid exclude glob {p}"))?;
        b.add(g);
    }
    b.build().context("build exclude globset")
}

/// `None` = no extra restriction (same as explicit `**/*`).
fn build_include_set(includes: &[String]) -> Result<Option<GlobSet>> {
    if includes.iter().any(|g| g == "**/*") {
        return Ok(None);
    }
    let mut b = GlobSetBuilder::new();
    for p in includes {
        let g = Glob::new(p).with_context(|| format!("invalid include glob {p}"))?;
        b.add(g);
    }
    Ok(Some(b.build().context("build include globset")?))
}

struct PathFilters {
    exclude: GlobSet,
    include: Option<GlobSet>,
}

impl PathFilters {
    fn from_policy(policy: &Policy) -> Result<Self> {
        Ok(Self {
            exclude: build_exclude_set(policy.scan.effective_exclude())?,
            include: build_include_set(policy.scan.effective_include())?,
        })
    }

    fn allows(&self, rel: &str) -> bool {
        if self.exclude.is_match(rel) {
            return false;
        }
        match &self.include {
            None => true,
            Some(set) => set.is_match(rel),
        }
    }
}

fn rel_normalized(full: &Path, root: &Path) -> String {
    full.strip_prefix(root)
        .unwrap_or(full)
        .to_string_lossy()
        .replace('\\', "/")
}

fn canonical_or_same(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn skipped_finding(rule_id: &str, rel: String, message: String) -> Finding {
    Finding {
        rule_id: rule_id.into(),
        severity: "info".into(),
        kind: "ignore".into(),
        file: rel,
        line: 1,
        column: 1,
        message,
        redacted_value: "[REDACTED]".into(),
        confidence: 1.0,
        context_before: vec![],
        context_after: vec![],
    }
}

fn scan_root_for_target(target: &Path) -> PathBuf {
    if target.is_dir() {
        target.to_path_buf()
    } else {
        target
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

fn policy_root_for_scan(target_root: &Path) -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cwd = canonical_or_same(&cwd);
    let target_root = canonical_or_same(target_root);
    if target_root.starts_with(&cwd) {
        cwd
    } else {
        target_root
    }
}

fn prepend_policy_warnings(head: Vec<Finding>, tail: Vec<Finding>) -> Vec<Finding> {
    let mut v = head;
    v.extend(tail);
    v
}

fn apply_scan_flag_overrides(policy: &mut Policy, opts: &ScanOptions) {
    if opts.include_binary {
        policy.scan.include_binary = true;
    }
    if opts.follow_symlinks {
        policy.scan.follow_symlinks = true;
    }
}

struct PreparedScan<'a> {
    policy: &'a Policy,
    allowlist: Vec<suppression::CompiledAllowlist>,
    custom: Vec<custom_rules::CompiledCustomRule>,
    cfg: shk_rules::RuleEngineConfig,
}

impl<'a> PreparedScan<'a> {
    fn new(policy: &'a Policy) -> Result<Self> {
        let cfg = policy.rule_engine_config();
        let custom = custom_rules::compile_for_policy(&policy.custom_rules, cfg.internal_terms)?;
        Ok(Self {
            policy,
            allowlist: suppression::compile_allowlist(&policy.allowlist)?,
            custom,
            cfg,
        })
    }
}

struct FindingDeduper {
    seen: HashSet<(String, String)>,
}

impl FindingDeduper {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    fn insert(&mut self, rule_id: &str, matched_text: &str) -> bool {
        self.seen
            .insert((rule_id.to_string(), matched_text.to_string()))
    }
}

struct ScanChunk {
    findings: Vec<Finding>,
    suppressed: u64,
    deduplicated: u64,
}

impl ScanChunk {
    fn empty() -> Self {
        Self {
            findings: vec![],
            suppressed: 0,
            deduplicated: 0,
        }
    }

    fn skipped(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            suppressed: 0,
            deduplicated: 0,
        }
    }
}

#[cfg(test)]
fn scan_text_content(
    rel: &str,
    content: &str,
    policy: &Policy,
    include_context: bool,
) -> Result<ScanChunk> {
    let prepared = PreparedScan::new(policy)?;
    scan_text_prepared(rel, content, &prepared, include_context)
}

fn scan_text_prepared(
    rel: &str,
    content: &str,
    prepared: &PreparedScan<'_>,
    include_context: bool,
) -> Result<ScanChunk> {
    let inline = suppression::parse_inline_suppressions(content);
    let mut suppressed = 0u64;
    let mut deduplicated = 0u64;
    let mut findings = Vec::new();
    let mut deduper = FindingDeduper::new();

    for mut m in shk_rules::scan_content(content, rel, &prepared.cfg) {
        if inline.is_suppressed(m.line, m.rule_id) {
            m.matched_text.zeroize();
            suppressed += 1;
            continue;
        }
        if suppression::suppressed_by_allowlist(
            rel,
            m.rule_id,
            &m.matched_text,
            &prepared.policy.allowlist,
            &prepared.allowlist,
        ) {
            m.matched_text.zeroize();
            suppressed += 1;
            continue;
        }
        if !deduper.insert(m.rule_id, &m.matched_text) {
            m.matched_text.zeroize();
            deduplicated += 1;
            continue;
        }
        findings.push(Finding::from_rule_match_with_custom_context(
            rel,
            &m,
            include_context,
            content,
            &prepared.cfg,
            &prepared.custom,
        ));
        m.matched_text.zeroize();
    }
    for mut m in custom_rules::scan_content(content, &prepared.custom) {
        if inline.is_suppressed(m.line, &m.rule_id) {
            m.matched_text.zeroize();
            suppressed += 1;
            continue;
        }
        if suppression::suppressed_by_allowlist(
            rel,
            &m.rule_id,
            &m.matched_text,
            &prepared.policy.allowlist,
            &prepared.allowlist,
        ) {
            m.matched_text.zeroize();
            suppressed += 1;
            continue;
        }
        if !deduper.insert(&m.rule_id, &m.matched_text) {
            m.matched_text.zeroize();
            deduplicated += 1;
            continue;
        }
        findings.push(Finding::from_custom_match(
            rel,
            &m,
            include_context,
            content,
            &prepared.cfg,
            &prepared.custom,
        ));
        m.matched_text.zeroize();
    }
    Ok(ScanChunk {
        findings,
        suppressed,
        deduplicated,
    })
}

fn scan_one_path(
    root: &Path,
    rel_path: &Path,
    label_root: &Path,
    prepared: &PreparedScan<'_>,
    include_context: bool,
) -> Result<ScanChunk> {
    let full = root.join(rel_path);
    let meta = match fs::metadata(&full) {
        Ok(m) => m,
        Err(_) => return Ok(ScanChunk::empty()),
    };
    if meta.is_dir() {
        return Ok(ScanChunk::empty());
    }
    let rel = rel_normalized(&full, label_root);
    if meta.len() > prepared.policy.scan.max_file_size_bytes {
        let f = vec![skipped_finding(
            "scan.file_too_large",
            rel,
            format!(
                "Skipped: file exceeds max_file_size_bytes ({})",
                prepared.policy.scan.max_file_size_bytes
            ),
        )];
        return Ok(ScanChunk::skipped(f));
    }
    let bytes = match fs::read(&full) {
        Ok(bytes) => bytes,
        Err(err) => {
            let f = vec![skipped_finding(
                "scan.file_read_error",
                rel,
                format!("Skipped: could not read file ({err})"),
            )];
            return Ok(ScanChunk::skipped(f));
        }
    };
    scan_bytes(&rel, bytes, prepared, include_context)
}

fn scan_staged_blob(
    repo: &Path,
    rel_path: &Path,
    prepared: &PreparedScan<'_>,
    include_context: bool,
) -> Result<ScanChunk> {
    let rel = rel_path.to_string_lossy().replace('\\', "/");
    let bytes = git::staged_file_bytes(repo, rel_path)?;
    scan_bytes(&rel, bytes, prepared, include_context)
}

fn scan_history_blob(
    repo: &Path,
    blob: &git::GitHistoryBlob,
    prepared: &PreparedScan<'_>,
    include_context: bool,
) -> Result<ScanChunk> {
    let rel = blob.path.to_string_lossy().replace('\\', "/");
    let label = history_display_label(blob);
    let bytes = git::history_blob_bytes(repo, &blob.oid)?;
    scan_bytes_with_display(&rel, &label, bytes, prepared, include_context)
}

fn history_display_label(blob: &git::GitHistoryBlob) -> String {
    format!(
        "{}:{}",
        blob.short_commit(),
        blob.path.to_string_lossy().replace('\\', "/")
    )
}

fn scan_bytes(
    rel: &str,
    bytes: Vec<u8>,
    prepared: &PreparedScan<'_>,
    include_context: bool,
) -> Result<ScanChunk> {
    scan_bytes_with_display(rel, rel, bytes, prepared, include_context)
}

fn scan_bytes_with_display(
    scan_rel: &str,
    display_rel: &str,
    mut bytes: Vec<u8>,
    prepared: &PreparedScan<'_>,
    include_context: bool,
) -> Result<ScanChunk> {
    if bytes.len() as u64 > prepared.policy.scan.max_file_size_bytes {
        let f = vec![skipped_finding(
            "scan.file_too_large",
            display_rel.to_string(),
            format!(
                "Skipped: file exceeds max_file_size_bytes ({})",
                prepared.policy.scan.max_file_size_bytes
            ),
        )];
        bytes.zeroize();
        return Ok(ScanChunk::skipped(f));
    }
    let take = prepared.policy.scan.binary_detection_bytes.min(bytes.len());
    if !prepared.policy.scan.include_binary && is_probably_binary(&bytes[..take]) {
        let f = vec![skipped_finding(
            "scan.binary_skipped",
            display_rel.to_string(),
            "Skipped: binary file (null byte in head)".into(),
        )];
        bytes.zeroize();
        return Ok(ScanChunk::skipped(f));
    }
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    let mut result = scan_text_prepared(scan_rel, &text, prepared, include_context);
    if scan_rel != display_rel
        && let Ok(chunk) = &mut result
    {
        for finding in &mut chunk.findings {
            finding.file = display_rel.to_string();
        }
    }
    text.zeroize();
    bytes.zeroize();
    result
}

/// Scan a single synthetic path (stdin / AI hook payloads) relative to configured project root `root`.
pub fn scan_string(
    root: &Path,
    rel_display_path: &str,
    content: &str,
    opts: ScanOptions,
) -> Result<ScanResult> {
    let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let (mut policy, policy_path) = Policy::load_from_dir(&root)?;
    apply_scan_flag_overrides(&mut policy, &opts);
    let include_context = opts.include_context || opts.json;
    let exit_threshold = if opts.use_pre_commit_threshold {
        opts.fail_on_override
            .unwrap_or_else(|| policy.pre_commit_fail_on())
    } else {
        opts.fail_on_override
            .unwrap_or_else(|| policy.scan_fail_on())
    };

    let expired = suppression::expired_allowlist_warnings(&policy.allowlist);
    let prepared = PreparedScan::new(&policy)?;
    let chunk = scan_text_prepared(rel_display_path, content, &prepared, include_context)?;
    let findings = prepend_policy_warnings(expired, chunk.findings);
    drop(prepared);

    Ok(ScanResult {
        findings,
        scanned_paths: vec![rel_display_path.to_string()],
        policy,
        policy_path,
        exit_threshold,
        suppressed: chunk.suppressed,
        deduplicated: chunk.deduplicated,
    })
}

pub fn scan_staged(cwd: &Path, opts: ScanOptions) -> Result<ScanResult> {
    let repo = git::discover_repo_root(cwd).context("not a git repository")?;
    let repo = fs::canonicalize(&repo).unwrap_or(repo);
    if !git::is_inside_git_work_tree(&repo) {
        bail!("shk scan --staged requires a Git repository");
    }
    let (mut policy, policy_path) = Policy::load_from_dir(&repo)?;
    apply_scan_flag_overrides(&mut policy, &opts);
    let paths = git::staged_files(&repo)?;
    let include_context = opts.include_context || opts.json;
    let mut findings = suppression::expired_allowlist_warnings(&policy.allowlist);
    let prepared = PreparedScan::new(&policy)?;
    let scanned: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();
    let chunk_results: Vec<Result<ScanChunk>> = paths
        .par_iter()
        .map(|rel| scan_staged_blob(&repo, rel, &prepared, include_context))
        .collect();
    let mut suppressed_total = 0u64;
    let mut deduplicated_total = 0u64;
    for chunk in chunk_results {
        let chunk = chunk?;
        findings.extend(chunk.findings);
        suppressed_total += chunk.suppressed;
        deduplicated_total += chunk.deduplicated;
    }
    let exit_threshold = if opts.use_pre_commit_threshold {
        opts.fail_on_override
            .unwrap_or_else(|| policy.pre_commit_fail_on())
    } else {
        opts.fail_on_override
            .unwrap_or_else(|| policy.scan_fail_on())
    };
    drop(prepared);
    Ok(ScanResult {
        findings,
        scanned_paths: scanned,
        policy,
        policy_path,
        exit_threshold,
        suppressed: suppressed_total,
        deduplicated: deduplicated_total,
    })
}

pub fn scan_git_history(cwd: &Path, opts: ScanOptions) -> Result<ScanResult> {
    let selection = select_git_history(cwd, &opts)?;
    let include_context = opts.include_context || opts.json;
    let exit_threshold = if opts.use_pre_commit_threshold {
        opts.fail_on_override
            .unwrap_or_else(|| selection.policy.pre_commit_fail_on())
    } else {
        opts.fail_on_override
            .unwrap_or_else(|| selection.policy.scan_fail_on())
    };

    let mut findings = suppression::expired_allowlist_warnings(&selection.policy.allowlist);
    let prepared = PreparedScan::new(&selection.policy)?;
    let scanned: Vec<String> = selection
        .filtered_blobs
        .iter()
        .map(history_display_label)
        .collect();
    let chunk_results: Vec<Result<ScanChunk>> = selection
        .filtered_blobs
        .par_iter()
        .map(|blob| scan_history_blob(&selection.repo, blob, &prepared, include_context))
        .collect();
    let mut suppressed_total = 0u64;
    let mut deduplicated_total = 0u64;
    for chunk in chunk_results {
        let chunk = chunk?;
        findings.extend(chunk.findings);
        suppressed_total += chunk.suppressed;
        deduplicated_total += chunk.deduplicated;
    }
    drop(prepared);
    Ok(ScanResult {
        findings,
        scanned_paths: scanned,
        policy: selection.policy,
        policy_path: selection.policy_path,
        exit_threshold,
        suppressed: suppressed_total,
        deduplicated: deduplicated_total,
    })
}

pub fn preview_git_history(cwd: &Path, opts: ScanOptions) -> Result<GitHistoryPreview> {
    let selection = select_git_history(cwd, &opts)?;
    let sample_paths = selection
        .filtered_blobs
        .iter()
        .take(10)
        .map(history_display_label)
        .collect();

    Ok(GitHistoryPreview {
        version: 1,
        mode: "git-history-preview".into(),
        scope: selection.history_opts.scope_label(),
        since: selection.history_opts.since,
        max_commits: selection.history_opts.max_commits,
        candidate_commits: selection.candidate_commits,
        candidate_paths: selection.candidate_paths,
        unique_blobs: selection.unique_blobs,
        policy_filtered_blobs: selection.filtered_blobs.len(),
        sample_paths,
        policy_path: selection
            .policy_path
            .as_ref()
            .map(|p| p.display().to_string()),
    })
}

fn select_git_history(cwd: &Path, opts: &ScanOptions) -> Result<GitHistorySelection> {
    let repo = git::discover_repo_root(cwd).context("not a git repository")?;
    let repo = fs::canonicalize(&repo).unwrap_or(repo);
    if !git::is_inside_git_work_tree(&repo) {
        bail!("shk scan --git-history requires a Git repository");
    }
    let (mut policy, policy_path) = Policy::load_from_dir(&repo)?;
    apply_scan_flag_overrides(&mut policy, opts);
    let filters = PathFilters::from_policy(&policy)?;
    let history_opts = git_history_options(opts);
    let inventory = git::history_inventory(&repo, &history_opts)?;
    let git::GitHistoryInventory {
        candidate_commits,
        candidate_paths,
        blobs,
    } = inventory;
    let unique_blobs = blobs.len();
    let filtered_blobs: Vec<_> = blobs
        .into_iter()
        .filter(|blob| filters.allows(&blob.path.to_string_lossy().replace('\\', "/")))
        .collect();

    Ok(GitHistorySelection {
        repo,
        policy,
        policy_path,
        history_opts,
        candidate_commits,
        candidate_paths,
        unique_blobs,
        filtered_blobs,
    })
}

pub fn scan_path(target: &Path, opts: ScanOptions) -> Result<ScanResult> {
    if opts.staged {
        return scan_staged(target, opts);
    }
    if opts.git_history {
        return scan_git_history(target, opts);
    }

    let scan_root = canonical_or_same(&scan_root_for_target(target));
    let policy_root = policy_root_for_scan(&scan_root);
    let (mut policy, policy_path) = Policy::load_from_dir(&policy_root)?;
    apply_scan_flag_overrides(&mut policy, &opts);
    let filters = PathFilters::from_policy(&policy)?;
    let include_context = opts.include_context || opts.json;
    let exit_threshold = if opts.use_pre_commit_threshold {
        opts.fail_on_override
            .unwrap_or_else(|| policy.pre_commit_fail_on())
    } else {
        opts.fail_on_override
            .unwrap_or_else(|| policy.scan_fail_on())
    };

    let mut suppressed_total = 0u64;
    let mut deduplicated_total = 0u64;
    let expired = suppression::expired_allowlist_warnings(&policy.allowlist);
    let prepared = PreparedScan::new(&policy)?;

    if target.is_file() {
        let abs_target = fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
        let rel = abs_target
            .strip_prefix(&policy_root)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| {
                target
                    .file_name()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."))
            });
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        if !filters.allows(&rel_s) {
            drop(prepared);
            return Ok(ScanResult {
                findings: expired,
                scanned_paths: vec![rel_s],
                policy,
                policy_path,
                exit_threshold,
                suppressed: 0,
                deduplicated: 0,
            });
        }
        let chunk = scan_one_path(
            &scan_root,
            abs_target
                .strip_prefix(&scan_root)
                .unwrap_or(abs_target.as_path()),
            &policy_root,
            &prepared,
            include_context,
        )?;
        suppressed_total += chunk.suppressed;
        deduplicated_total += chunk.deduplicated;
        let findings = prepend_policy_warnings(expired, chunk.findings);
        drop(prepared);
        return Ok(ScanResult {
            findings,
            scanned_paths: vec![rel_s],
            policy,
            policy_path,
            exit_threshold,
            suppressed: suppressed_total,
            deduplicated: deduplicated_total,
        });
    }

    let mut walk = WalkBuilder::new(&scan_root);
    walk.hidden(false);
    walk.git_ignore(true);
    walk.git_exclude(true);
    walk.standard_filters(true);
    if policy.scan.follow_symlinks {
        walk.follow_links(true);
    }

    let entries: Vec<_> = walk.build().collect();
    let scanned_files: Vec<PathBuf> = entries
        .into_par_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.into_path())
        .filter(|full| {
            let rel = rel_normalized(full, &policy_root);
            filters.allows(&rel)
        })
        .collect();

    let chunk_results: Vec<Result<ScanChunk>> = scanned_files
        .par_iter()
        .map(|full| {
            let rel = full.strip_prefix(&scan_root).unwrap_or(full).to_path_buf();
            scan_one_path(&scan_root, &rel, &policy_root, &prepared, include_context)
        })
        .collect();

    let mut findings = expired;
    for chunk in chunk_results {
        let chunk = chunk?;
        findings.extend(chunk.findings);
        suppressed_total += chunk.suppressed;
        deduplicated_total += chunk.deduplicated;
    }

    let scanned_paths: Vec<String> = scanned_files
        .iter()
        .map(|p| rel_normalized(p, &policy_root))
        .collect();
    drop(prepared);

    Ok(ScanResult {
        findings,
        scanned_paths,
        policy,
        policy_path,
        exit_threshold,
        suppressed: suppressed_total,
        deduplicated: deduplicated_total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AllowlistEntry, CustomRule, Policy};

    #[test]
    fn path_filters_include_glob() {
        let mut p = Policy::default();
        p.scan.include = Some(vec!["**/only-me.txt".into()]);
        p.scan.exclude = Some(vec![]);
        let f = PathFilters::from_policy(&p).unwrap();
        assert!(f.allows("foo/only-me.txt"));
        assert!(!f.allows("foo/other.txt"));
    }

    #[test]
    fn path_filters_default_include_all() {
        let p = Policy::default();
        let f = PathFilters::from_policy(&p).unwrap();
        assert!(f.allows("anything.rs"));
    }

    #[test]
    fn path_filters_explicit_empty_include_scans_nothing() {
        let mut p = Policy::default();
        p.scan.include = Some(vec![]);
        p.scan.exclude = Some(vec![]);
        let f = PathFilters::from_policy(&p).unwrap();
        assert!(!f.allows("anything.rs"));
    }

    #[test]
    fn allowlist_suppresses_match() {
        // not real credential: synthetic detector fixture value only
        let secret = r#"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"#;
        let hash = suppression::compute_value_hmac("secret.openai_api_key", secret);
        let mut p = Policy::default();
        p.allowlist.push(AllowlistEntry {
            rule_id: Some("secret.openai_api_key".into()),
            path: "**/*".into(),
            value_hash: Some(hash.clone()),
            reason: Some("fixture".into()),
            expires: None,
        });
        let compiled = suppression::compile_allowlist(&p.allowlist).unwrap();
        assert!(
            suppression::suppressed_by_allowlist(
                "dummy.txt",
                "secret.openai_api_key",
                secret,
                &p.allowlist,
                &compiled
            ),
            "hash {hash}"
        );
    }

    #[test]
    fn inline_suppression_reduces_emitted_findings() {
        // not real credential: synthetic detector fixture value only
        let text = "# shk-ignore-next-line secret.openai_api_key\nsk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n";
        let p = Policy::default();
        let chunk = scan_text_content("w.txt", text, &p, false).unwrap();
        assert!(
            chunk.suppressed >= 1,
            "expect suppression: findings={:?}",
            chunk.findings
        );
        assert!(
            !chunk
                .findings
                .iter()
                .any(|x| x.rule_id == "secret.openai_api_key"),
            "{:?}",
            chunk.findings
        );
    }

    #[test]
    fn duplicate_builtin_matches_emit_once_per_file_rule_and_value() {
        // not real credential: synthetic detector fixture value only
        let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
        let text = format!("{secret}\nlet copied = \"{secret}\";\n");
        let p = Policy::default();
        let chunk = scan_text_content("w.txt", &text, &p, false).unwrap();

        assert_eq!(chunk.suppressed, 0);
        assert_eq!(chunk.deduplicated, 1);
        let matches: Vec<_> = chunk
            .findings
            .iter()
            .filter(|f| f.rule_id == "secret.openai_api_key")
            .collect();
        assert_eq!(matches.len(), 1, "{:?}", chunk.findings);
        assert_eq!(matches[0].line, 1);
    }

    #[test]
    fn custom_rules_detect_project_terms() {
        let mut p = Policy::default();
        p.rules.internal_terms = true;
        p.custom_rules.push(CustomRule {
            id: "internal.project_codename".into(),
            pattern: "ProjectNebula|社外秘".into(),
            severity: "high".into(),
            kind: "internal".into(),
            message: Some("Internal confidential term detected".into()),
            confidence: Some(0.95),
            case_insensitive: false,
            enabled: true,
        });

        let chunk = scan_text_content("notes.txt", "launch ProjectNebula\n", &p, true).unwrap();

        assert_eq!(chunk.suppressed, 0);
        let f = chunk
            .findings
            .iter()
            .find(|f| f.rule_id == "internal.project_codename")
            .expect("custom finding");
        assert_eq!(f.severity, "high");
        assert_eq!(f.kind, "internal");
        assert_eq!(f.redacted_value, "[REDACTED]");
    }

    #[test]
    fn internal_custom_rules_are_disabled_by_default() {
        let mut p = Policy::default();
        p.custom_rules.push(CustomRule {
            id: "internal.project_codename".into(),
            pattern: "ProjectNebula".into(),
            severity: "high".into(),
            kind: "internal".into(),
            message: None,
            confidence: None,
            case_insensitive: false,
            enabled: true,
        });

        let chunk = scan_text_content("notes.txt", "launch ProjectNebula\n", &p, false).unwrap();

        assert!(chunk.findings.is_empty(), "{:?}", chunk.findings);
        assert_eq!(chunk.suppressed, 0);
    }

    #[test]
    fn custom_rules_respect_allowlist() {
        let mut p = Policy::default();
        p.rules.internal_terms = true;
        p.custom_rules.push(CustomRule {
            id: "internal.project_codename".into(),
            pattern: "ProjectNebula".into(),
            severity: "high".into(),
            kind: "internal".into(),
            message: None,
            confidence: None,
            case_insensitive: false,
            enabled: true,
        });
        p.allowlist.push(AllowlistEntry {
            rule_id: Some("internal.project_codename".into()),
            path: "docs/**".into(),
            value_hash: None,
            reason: Some("public roadmap".into()),
            expires: None,
        });

        let chunk = scan_text_content("docs/roadmap.md", "ProjectNebula\n", &p, false).unwrap();

        assert!(chunk.findings.is_empty(), "{:?}", chunk.findings);
        assert_eq!(chunk.suppressed, 1);
    }
}
