use crate::custom_rules;
use crate::document_masker;
use crate::finding::{ContextGuard, Finding, ScanJsonReport, ScanSummary};
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

/// All fields default to the plain `shk scan <path>` behavior (no git modes,
/// no overrides). Construct with struct-update syntax so new options do not
/// ripple through every call site: `ScanOptions { json: true, ..Default::default() }`.
#[derive(Default)]
pub struct ScanOptions {
    pub staged: bool,
    pub changed_since: Option<String>,
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
    /// Force secret/PII rules on and bypass allowlist/inline suppression.
    /// Intended for post-transform leftover checks, not normal scans.
    pub sensitive_check: bool,
    /// Explicit policy root for filesystem scans (where `shk.toml` lives).
    /// Git scan modes resolve policy from the repository root. When `None`,
    /// filesystem scans resolve policy relative to the process working
    /// directory (CLI behavior).
    /// GUI callers whose working directory is unrelated to the scanned
    /// project (e.g. the desktop app launched from Finder with cwd `/`) must
    /// set this to the project root, otherwise allowlist/exclude entries in
    /// the project `shk.toml` are silently ignored.
    pub policy_root: Option<PathBuf>,
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
        self.to_json_report_with_value_hash(color_mode, false)
    }

    pub fn to_json_report_with_value_hash(
        &self,
        color_mode: ColorMode,
        include_value_hash: bool,
    ) -> ScanJsonReport {
        let mut by_sev: BTreeMap<String, usize> = BTreeMap::new();
        for f in &self.findings {
            *by_sev.entry(f.severity.clone()).or_insert(0) += 1;
        }
        let mut findings = self.findings.clone();
        if !include_value_hash {
            for finding in &mut findings {
                finding.value_hash = None;
            }
        }
        ScanJsonReport {
            version: 1,
            scanned_paths: self.scanned_paths.clone(),
            findings,
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

/// UTF-16 encoding named by a leading byte order mark, if any.
fn utf16_bom_encoding(bytes: &[u8]) -> Option<&'static encoding_rs::Encoding> {
    // `FF FE 00 00` is the UTF-32LE mark, which starts like the UTF-16LE one.
    if bytes.starts_with(&[0xff, 0xfe, 0x00, 0x00]) {
        return None;
    }
    match encoding_rs::Encoding::for_bom(bytes) {
        Some((encoding, _))
            if encoding == encoding_rs::UTF_16LE || encoding == encoding_rs::UTF_16BE =>
        {
            Some(encoding)
        }
        _ => None,
    }
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

/// Whether the policy's `[scan]` include / exclude patterns would skip `rel`,
/// a policy-root-relative path using `/` separators. `scan_path` reports an
/// excluded single-file target as scanned with no findings, so callers that
/// need "was this file actually inspected" must ask first.
pub fn path_is_excluded(policy: &Policy, rel: &str) -> Result<bool> {
    Ok(!PathFilters::from_policy(policy)?.allows(rel))
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
        value_hash: None,
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
    apply_suppressions: bool,
}

impl<'a> PreparedScan<'a> {
    fn new(policy: &'a Policy) -> Result<Self> {
        Self::with_suppressions(policy, true)
    }

    fn with_suppressions(policy: &'a Policy, apply_suppressions: bool) -> Result<Self> {
        let cfg = policy.rule_engine_config();
        let custom = custom_rules::compile_for_policy(&policy.custom_rules, cfg.internal_terms)?;
        Ok(Self {
            policy,
            allowlist: suppression::compile_allowlist(&policy.allowlist)?,
            custom,
            cfg,
            apply_suppressions,
        })
    }
}

struct FindingDeduper {
    /// Rule-scoped digests, never raw matched values.
    seen: HashSet<(String, String)>,
}

impl FindingDeduper {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    fn insert(&mut self, rule_id: &str, matched_text: &str) -> bool {
        let digest = suppression::compute_value_hmac(rule_id, matched_text);
        self.seen.insert((rule_id.to_string(), digest))
    }
}

struct ScanChunk {
    findings: Vec<Finding>,
    suppressed: u64,
    deduplicated: u64,
    scanned: bool,
}

impl ScanChunk {
    fn empty() -> Self {
        Self {
            findings: vec![],
            suppressed: 0,
            deduplicated: 0,
            scanned: false,
        }
    }

    fn skipped(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            suppressed: 0,
            deduplicated: 0,
            scanned: true,
        }
    }

    fn append(&mut self, mut other: Self) {
        self.findings.append(&mut other.findings);
        self.suppressed += other.suppressed;
        self.deduplicated += other.deduplicated;
        self.scanned |= other.scanned;
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
    // A leading byte order mark is not part of the first line: left in place
    // it hides that line from line-anchored rules and shifts its columns.
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let inline = suppression::parse_inline_suppressions(content);
    let mut suppressed = 0u64;
    let mut deduplicated = 0u64;
    let mut findings = Vec::new();
    let mut deduper = FindingDeduper::new();

    let rule_matches = shk_rules::scan_content(content, rel, &prepared.cfg);
    let custom_matches = custom_rules::scan_content(content, &prepared.custom);
    // Context lines are redacted line by line, so anything that only matches
    // across lines (suppressed matches included) is registered up front.
    let context_guard = include_context.then(|| {
        let mut guard = ContextGuard::for_content(content);
        for m in &rule_matches {
            guard.add_match(content, m.line, m.column, &m.matched_text);
        }
        for m in &custom_matches {
            guard.add_match(content, m.line, m.column, &m.matched_text);
        }
        guard
    });
    let context_guard = context_guard.as_ref();

    for mut m in rule_matches {
        if prepared.apply_suppressions && inline.is_suppressed(m.line, m.rule_id) {
            m.matched_text.zeroize();
            suppressed += 1;
            continue;
        }
        if prepared.apply_suppressions
            && suppression::suppressed_by_allowlist(
                rel,
                m.rule_id,
                &m.matched_text,
                &prepared.policy.allowlist,
                &prepared.allowlist,
            )
        {
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
            context_guard,
            content,
            &prepared.cfg,
            &prepared.custom,
        ));
        m.matched_text.zeroize();
    }
    for mut m in custom_matches {
        if prepared.apply_suppressions && inline.is_suppressed(m.line, &m.rule_id) {
            m.matched_text.zeroize();
            suppressed += 1;
            continue;
        }
        if prepared.apply_suppressions
            && suppression::suppressed_by_allowlist(
                rel,
                &m.rule_id,
                &m.matched_text,
                &prepared.policy.allowlist,
                &prepared.allowlist,
            )
        {
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
            context_guard,
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
        scanned: true,
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
    size: u64,
    prepared: &PreparedScan<'_>,
    include_context: bool,
) -> Result<ScanChunk> {
    let rel = rel_path.to_string_lossy().replace('\\', "/");
    if size > prepared.policy.scan.max_file_size_bytes {
        return Ok(ScanChunk::skipped(vec![skipped_finding(
            "scan.file_too_large",
            rel,
            format!(
                "Skipped: file exceeds max_file_size_bytes ({})",
                prepared.policy.scan.max_file_size_bytes
            ),
        )]));
    }
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
    if blob.size > prepared.policy.scan.max_file_size_bytes {
        return Ok(ScanChunk::skipped(vec![skipped_finding(
            "scan.file_too_large",
            label,
            format!(
                "Skipped: file exceeds max_file_size_bytes ({})",
                prepared.policy.scan.max_file_size_bytes
            ),
        )]));
    }
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
    let mut notes = Vec::new();
    match scan_document_bytes(scan_rel, display_rel, &bytes, prepared, include_context) {
        Ok(Some(chunk)) => {
            bytes.zeroize();
            return Ok(chunk);
        }
        Ok(None) => {}
        Err(err) => {
            // A document extension does not make the content a document: a
            // renamed text file or a damaged archive is still scanned as raw
            // bytes below, and the note records why extraction was skipped.
            notes.push(skipped_finding(
                "scan.file_read_error",
                display_rel.to_string(),
                format!(
                    "Could not read document text ({err}); scanned the raw file content instead"
                ),
            ));
        }
    }
    // UTF-16 text is full of NUL bytes, so a byte order mark is checked
    // before the binary heuristic.
    let utf16 = utf16_bom_encoding(&bytes);
    let take = prepared.policy.scan.binary_detection_bytes.min(bytes.len());
    if utf16.is_none() && !prepared.policy.scan.include_binary && is_probably_binary(&bytes[..take])
    {
        notes.push(skipped_finding(
            "scan.binary_skipped",
            display_rel.to_string(),
            "Skipped: binary file (null byte in head)".into(),
        ));
        bytes.zeroize();
        return Ok(ScanChunk::skipped(notes));
    }
    let (mut text, lossy) = match utf16 {
        Some(encoding) => {
            // `decode` strips the byte order mark it sniffs.
            let (decoded, _, malformed) = encoding.decode(&bytes);
            (decoded.into_owned(), malformed)
        }
        None => (
            String::from_utf8_lossy(&bytes).into_owned(),
            std::str::from_utf8(&bytes).is_err(),
        ),
    };
    let non_utf8 = lossy && utf16.is_none();
    let mut result = scan_text_prepared(scan_rel, &text, prepared, include_context);
    if scan_rel != display_rel
        && let Ok(chunk) = &mut result
    {
        rewrite_finding_paths(&mut chunk.findings, display_rel);
    }
    if let Ok(chunk) = &mut result {
        chunk.findings.append(&mut notes);
    }
    if lossy
        && utf16.is_some()
        && let Ok(chunk) = &mut result
    {
        chunk.findings.push(skipped_finding(
            "scan.non_utf8_lossy",
            display_rel.to_string(),
            "File has a UTF-16 byte order mark but is not valid UTF-16; scanned with lossy decoding — detection may be incomplete"
                .into(),
        ));
    }
    if non_utf8 && let Ok(chunk) = &mut result {
        // Lossy decoding garbles legacy encodings (e.g. Shift-JIS), so
        // pattern detection on this file may be incomplete. Surface that
        // instead of silently reporting the file as clean.
        chunk.findings.push(skipped_finding(
            "scan.non_utf8_lossy",
            display_rel.to_string(),
            "File is not valid UTF-8; scanned with lossy decoding — detection may be incomplete"
                .into(),
        ));
    }
    text.zeroize();
    bytes.zeroize();
    result
}

fn scan_document_bytes(
    scan_rel: &str,
    display_rel: &str,
    bytes: &[u8],
    prepared: &PreparedScan<'_>,
    include_context: bool,
) -> Result<Option<ScanChunk>> {
    let Some(entries) = document_masker::extract_document_text_entries(
        scan_rel,
        bytes,
        prepared.policy.scan.max_file_size_bytes,
    )?
    else {
        return Ok(None);
    };
    if entries.is_empty() {
        let f = vec![skipped_finding(
            "scan.document_text_empty",
            display_rel.to_string(),
            "Skipped: document contains no extractable text".into(),
        )];
        return Ok(Some(ScanChunk::skipped(f)));
    }

    let mut combined = ScanChunk::empty();
    for mut entry in entries {
        let scan_label = document_entry_label(scan_rel, &entry.entry_path);
        let display_label = document_entry_label(display_rel, &entry.entry_path);
        let chunk_result = scan_text_prepared(&scan_label, &entry.text, prepared, include_context);
        entry.text.zeroize();
        let mut chunk = chunk_result?;
        if scan_label != display_label {
            rewrite_finding_paths(&mut chunk.findings, &display_label);
        }
        combined.append(chunk);
    }

    Ok(Some(combined))
}

fn document_entry_label(base: &str, entry_path: &str) -> String {
    if entry_path.is_empty() {
        base.to_string()
    } else {
        format!("{base}:{entry_path}")
    }
}

fn rewrite_finding_paths(findings: &mut [Finding], display_rel: &str) {
    for finding in findings {
        finding.file = display_rel.to_string();
    }
}

/// Scan a single synthetic path (stdin / AI hook payloads) relative to configured project root `root`.
pub fn scan_string(
    root: &Path,
    rel_display_path: &str,
    content: &str,
    opts: ScanOptions,
) -> Result<ScanResult> {
    scan_strings(root, &[(rel_display_path, content)], opts)
}

/// Scan several synthetic paths, each `(rel_display_path, content)`, with one
/// policy load. AI hook payloads use this so path-scoped policy (allowlist
/// rows, rule path filters) only applies to the text under its own path.
pub fn scan_strings(root: &Path, parts: &[(&str, &str)], opts: ScanOptions) -> Result<ScanResult> {
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
    let mut findings = Vec::new();
    let mut suppressed = 0;
    let mut deduplicated = 0;
    for (rel_display_path, content) in parts {
        let chunk = scan_text_prepared(rel_display_path, content, &prepared, include_context)?;
        findings.extend(chunk.findings);
        suppressed += chunk.suppressed;
        deduplicated += chunk.deduplicated;
    }
    let findings = prepend_policy_warnings(expired, findings);
    drop(prepared);

    Ok(ScanResult {
        findings,
        scanned_paths: parts.iter().map(|(path, _)| path.to_string()).collect(),
        policy,
        policy_path,
        exit_threshold,
        suppressed,
        deduplicated,
    })
}

pub fn scan_staged(cwd: &Path, opts: ScanOptions) -> Result<ScanResult> {
    let repo = git::discover_repo_root(cwd).context("not a git repository")?;
    let repo = fs::canonicalize(&repo).unwrap_or(repo);
    if !git::is_inside_git_work_tree(&repo) {
        bail!("shk scan --staged requires a Git repository");
    }
    let blobs = git::staged_blobs(&repo)?;
    let sizes = blobs
        .iter()
        .map(|blob| (blob.path.clone(), blob.size))
        .collect::<std::collections::HashMap<_, _>>();
    let paths = blobs.into_iter().map(|blob| blob.path).collect();
    scan_git_rel_paths(
        &repo,
        paths,
        &opts,
        |repo, rel, prepared, include_context| {
            let size = sizes
                .get(rel)
                .copied()
                .context("missing staged blob size")?;
            scan_staged_blob(repo, rel, size, prepared, include_context)
        },
    )
}

pub fn scan_changed_since(cwd: &Path, base: &str, opts: ScanOptions) -> Result<ScanResult> {
    let repo = git::discover_repo_root(cwd).context("not a git repository")?;
    let repo = fs::canonicalize(&repo).unwrap_or(repo);
    if !git::is_inside_git_work_tree(&repo) {
        bail!("shk scan --changed-since requires a Git repository");
    }
    let paths = git::changed_files_since(&repo, base)?;
    scan_git_rel_paths(
        &repo,
        paths,
        &opts,
        |repo, rel, prepared, include_context| {
            scan_changed_worktree_path(repo, rel, prepared, include_context)
        },
    )
}

fn scan_changed_worktree_path(
    repo: &Path,
    rel_path: &Path,
    prepared: &PreparedScan<'_>,
    include_context: bool,
) -> Result<ScanChunk> {
    let full = repo.join(rel_path);
    let meta = match fs::symlink_metadata(&full) {
        Ok(m) => m,
        Err(_) => return Ok(ScanChunk::empty()),
    };
    if meta.file_type().is_symlink() && !prepared.policy.scan.follow_symlinks {
        return Ok(ScanChunk::empty());
    }
    scan_one_path(repo, rel_path, repo, prepared, include_context)
}

fn scan_git_rel_paths(
    repo: &Path,
    paths: Vec<PathBuf>,
    opts: &ScanOptions,
    scan_file: impl Fn(&Path, &Path, &PreparedScan<'_>, bool) -> Result<ScanChunk> + Sync,
) -> Result<ScanResult> {
    let (mut policy, policy_path) = Policy::load_from_dir(repo)?;
    apply_scan_flag_overrides(&mut policy, opts);
    let filters = PathFilters::from_policy(&policy)?;
    let include_context = opts.include_context || opts.json;
    let mut findings = suppression::expired_allowlist_warnings(&policy.allowlist);
    let prepared = PreparedScan::new(&policy)?;
    let filtered_paths: Vec<PathBuf> = paths
        .into_iter()
        .filter(|p| {
            let rel = p.to_string_lossy().replace('\\', "/");
            filters.allows(&rel)
        })
        .collect();
    let chunk_results: Vec<Result<ScanChunk>> = filtered_paths
        .par_iter()
        .map(|rel| scan_file(repo, rel, &prepared, include_context))
        .collect();
    let mut scanned = Vec::new();
    let mut suppressed_total = 0u64;
    let mut deduplicated_total = 0u64;
    for (rel, chunk) in filtered_paths.iter().zip(chunk_results) {
        let chunk = chunk?;
        if chunk.scanned {
            scanned.push(rel.to_string_lossy().replace('\\', "/"));
        }
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
    // Path filters run before blobs are deduplicated: a blob committed under
    // both an excluded and an included path must still be scanned.
    let inventory =
        git::history_inventory_filtered(&repo, &history_opts, |rel| filters.allows(rel))?;
    let git::GitHistoryInventory {
        candidate_commits,
        candidate_paths,
        unique_blobs,
        blobs: filtered_blobs,
    } = inventory;

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
    if let Some(base) = opts.changed_since.clone() {
        return scan_changed_since(target, &base, opts);
    }
    if opts.git_history {
        return scan_git_history(target, opts);
    }

    if !target.exists() {
        bail!("scan target does not exist: {}", target.display());
    }

    let scan_root = canonical_or_same(&scan_root_for_target(target));
    let policy_root = match &opts.policy_root {
        Some(root) => {
            if !root.is_dir() {
                bail!("policy root is not a directory: {}", root.display());
            }
            canonical_or_same(root)
        }
        None => policy_root_for_scan(&scan_root),
    };
    let (mut policy, policy_path) = Policy::load_from_dir(&policy_root)?;
    apply_scan_flag_overrides(&mut policy, &opts);
    if opts.sensitive_check {
        policy.rules.secrets = true;
        policy.rules.pii = true;
        policy.rules.pii_languages = vec!["en".into(), "ja".into()];
        policy.allowlist.clear();
    }
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
    let prepared = PreparedScan::with_suppressions(&policy, !opts.sensitive_check)?;

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
    // standard_filters must come first: it resets every filter (including
    // hidden) and would otherwise override hidden(false) below.
    walk.standard_filters(true);
    walk.hidden(false);
    walk.git_ignore(true);
    walk.git_exclude(true);
    // With hidden files included, keep the walker out of .git itself.
    walk.filter_entry(|e| e.file_name() != std::ffi::OsStr::new(".git"));
    if policy.scan.follow_symlinks {
        walk.follow_links(true);
    }

    let mut findings = expired;
    let mut scanned_files: Vec<PathBuf> = Vec::new();
    for entry in walk.build() {
        let entry = match entry {
            Ok(entry) => entry,
            // Surface walk errors (permission denied, broken links, …) as
            // info findings instead of silently skipping whole subtrees.
            Err(err) => {
                findings.push(skipped_finding(
                    "scan.walk_error",
                    "<walk>".into(),
                    format!("Skipped: directory walk error ({err})"),
                ));
                continue;
            }
        };
        // DirEntry::file_type() does not follow symlinks unless the walker
        // was built with follow_links(true), so symlinked files (which may
        // point outside the repository) are excluded when
        // follow_symlinks = false.
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let full = entry.into_path();
        let rel = rel_normalized(&full, &policy_root);
        if filters.allows(&rel) {
            scanned_files.push(full);
        }
    }

    let chunk_results: Vec<Result<ScanChunk>> = scanned_files
        .par_iter()
        .map(|full| {
            let rel = full.strip_prefix(&scan_root).unwrap_or(full).to_path_buf();
            scan_one_path(&scan_root, &rel, &policy_root, &prepared, include_context)
        })
        .collect();

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
    fn finding_deduper_keeps_only_rule_scoped_digest() {
        let raw = "synthetic-secret-value";
        let mut deduper = FindingDeduper::new();

        assert!(deduper.insert("secret.test", raw));
        assert!(!deduper.insert("secret.test", raw));
        assert!(deduper.seen.iter().all(|(_, value)| value != raw));
    }

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
            unknown: Default::default(),
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
            unknown: Default::default(),
        });

        let chunk = scan_text_content("docs/roadmap.md", "ProjectNebula\n", &p, false).unwrap();

        assert!(chunk.findings.is_empty(), "{:?}", chunk.findings);
        assert_eq!(chunk.suppressed, 1);
    }

    #[test]
    fn scan_path_rejects_missing_target() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.txt");
        let result = scan_path(&missing, ScanOptions::default());
        match result {
            Err(err) => assert!(err.to_string().contains("scan target does not exist")),
            Ok(_) => panic!("missing target should fail"),
        }
    }

    #[test]
    fn scan_path_rejects_invalid_explicit_policy_root() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        fs::write(&target, "nothing here\n").unwrap();
        let missing_root = dir.path().join("missing");
        let result = scan_path(
            &target,
            ScanOptions {
                policy_root: Some(missing_root),
                ..ScanOptions::default()
            },
        );

        match result {
            Err(err) => assert!(err.to_string().contains("policy root is not a directory")),
            Ok(_) => panic!("invalid policy root should fail"),
        }
    }

    #[test]
    fn scan_path_uses_explicit_policy_root_over_cwd_heuristic() {
        let project = tempfile::tempdir().unwrap();
        // Project policy excludes the fixtures directory entirely.
        fs::write(
            project.path().join("shk.toml"),
            "[scan]\nexclude = [\"fixtures/**\"]\n",
        )
        .unwrap();
        let fixtures = project.path().join("fixtures");
        fs::create_dir(&fixtures).unwrap();
        // not real credential: synthetic detector fixture value only
        fs::write(
            fixtures.join("secret.txt"),
            "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
        )
        .unwrap();

        // Scanning the subdirectory without an explicit policy root loses the
        // project policy (neither cwd nor the target dir holds shk.toml).
        let res = scan_path(&fixtures, ScanOptions::default()).unwrap();
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.starts_with("secret.")),
            "without policy_root the project exclude must not apply: {:?}",
            res.findings
        );

        // GUI callers pass the project root explicitly and get the same
        // result as `shk scan` run from the project root.
        let opts = ScanOptions {
            policy_root: Some(project.path().to_path_buf()),
            ..ScanOptions::default()
        };
        let res = scan_path(&fixtures, opts).unwrap();
        assert!(res.policy_path.is_some(), "project shk.toml must be loaded");
        assert!(
            res.findings.is_empty(),
            "excluded fixtures must not produce findings: {:?}",
            res.findings
        );
    }

    #[cfg(unix)]
    #[test]
    fn scan_skips_symlinked_files_when_follow_symlinks_disabled() {
        let outside = tempfile::tempdir().unwrap();
        let secret_path = outside.path().join("secret.txt");
        // not real credential: synthetic detector fixture value only
        fs::write(
            &secret_path,
            "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
        )
        .unwrap();

        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("clean.txt"), "nothing here\n").unwrap();
        std::os::unix::fs::symlink(&secret_path, root.path().join("link.txt")).unwrap();

        let res = scan_path(root.path(), ScanOptions::default()).unwrap();

        assert!(
            !res.scanned_paths.iter().any(|p| p.contains("link.txt")),
            "symlinked file must not be read when follow_symlinks=false: {:?}",
            res.scanned_paths
        );
        assert!(res.findings.is_empty(), "{:?}", res.findings);
    }

    #[test]
    fn scan_reports_non_utf8_text_as_lossy() {
        let root = tempfile::tempdir().unwrap();
        // Shift-JIS encoded 「秘密」 — invalid UTF-8 but no NUL bytes.
        fs::write(root.path().join("sjis.txt"), [0x94, 0xe9, 0x96, 0xa7, 0x0a]).unwrap();

        let res = scan_path(root.path(), ScanOptions::default()).unwrap();

        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "scan.non_utf8_lossy"),
            "{:?}",
            res.findings
        );
    }

    // not real credential: synthetic detector fixture value only
    fn synthetic_openai_key() -> String {
        format!("sk-proj-{}", "abcdefghijklmnopqrstuvwxyz0123456789")
    }

    fn git_ok(dir: &Path, args: &[&str]) {
        let email = format!("user.email=shk@{}", "example.invalid");
        let out = std::process::Command::new("git")
            .args(["-c", "user.name=shk test", "-c", &email])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn git_history_scans_blob_shared_by_excluded_and_included_paths() {
        let repo = tempfile::tempdir().unwrap();
        git_ok(repo.path(), &["init", "-q"]);
        fs::write(
            repo.path().join("shk.toml"),
            "[scan]\nexclude = [\"excluded/**\"]\n",
        )
        .unwrap();
        // `excluded/` sorts first, so it is the path Git reports first.
        for sub in ["excluded", "src"] {
            fs::create_dir_all(repo.path().join(sub)).unwrap();
            fs::write(
                repo.path().join(sub).join("same.txt"),
                format!("{}\n", synthetic_openai_key()),
            )
            .unwrap();
        }
        git_ok(repo.path(), &["add", "-A"]);
        git_ok(repo.path(), &["commit", "-q", "-m", "dupes"]);

        let res = scan_git_history(repo.path(), ScanOptions::default()).unwrap();
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "secret.openai_api_key" && f.file.ends_with(":src/same.txt")),
            "{:?}",
            res.findings
        );
        assert!(
            !res.scanned_paths.iter().any(|p| p.contains("excluded/")),
            "{:?}",
            res.scanned_paths
        );

        let preview = preview_git_history(repo.path(), ScanOptions::default()).unwrap();
        // shk.toml and the shared blob: two unique blobs, both scannable.
        assert_eq!(preview.unique_blobs, 2);
        assert_eq!(preview.policy_filtered_blobs, 2);
    }

    #[test]
    fn document_extraction_failure_falls_back_to_text_scan() {
        let root = tempfile::tempdir().unwrap();
        let names = ["notes.pdf", "notes.docx", "notes.xlsx", "notes.pptx"];
        for (idx, name) in names.iter().enumerate() {
            // Distinct values so per-file results do not depend on each other.
            fs::write(
                root.path().join(name),
                format!("not a real document\n{}{idx}\n", synthetic_openai_key()),
            )
            .unwrap();
        }

        let res = scan_path(root.path(), ScanOptions::default()).unwrap();
        for name in names {
            assert!(
                res.findings
                    .iter()
                    .any(|f| f.rule_id == "secret.openai_api_key" && f.file == name && f.line == 2),
                "{name}: {:?}",
                res.findings
            );
            assert!(
                res.findings
                    .iter()
                    .any(|f| f.rule_id == "scan.file_read_error" && f.file == name),
                "{name}: {:?}",
                res.findings
            );
        }
    }

    #[test]
    fn document_extraction_failure_on_binary_keeps_both_info_findings() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("broken.docx"), b"PK\x03\x04\x00\x00junk").unwrap();

        let res = scan_path(root.path(), ScanOptions::default()).unwrap();
        for rule in ["scan.file_read_error", "scan.binary_skipped"] {
            assert!(
                res.findings.iter().any(|f| f.rule_id == rule),
                "{rule}: {:?}",
                res.findings
            );
        }
    }

    fn utf16_bytes(text: &str, big_endian: bool) -> Vec<u8> {
        let mut out = if big_endian {
            vec![0xfe, 0xff]
        } else {
            vec![0xff, 0xfe]
        };
        for unit in text.encode_utf16() {
            out.extend(if big_endian {
                unit.to_be_bytes()
            } else {
                unit.to_le_bytes()
            });
        }
        out
    }

    #[test]
    fn utf16_text_with_bom_is_decoded_and_scanned() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("le.txt"),
            utf16_bytes(
                &format!("clean line\nkey {}L\n", synthetic_openai_key()),
                false,
            ),
        )
        .unwrap();
        fs::write(
            root.path().join("be.txt"),
            utf16_bytes(
                &format!("clean line\nkey {}B\n", synthetic_openai_key()),
                true,
            ),
        )
        .unwrap();

        let res = scan_path(root.path(), ScanOptions::default()).unwrap();
        for name in ["le.txt", "be.txt"] {
            let hit = res
                .findings
                .iter()
                .find(|f| f.rule_id == "secret.openai_api_key" && f.file == name)
                .unwrap_or_else(|| panic!("{name}: {:?}", res.findings));
            assert_eq!((hit.line, hit.column), (2, 5), "{name}");
        }
        assert!(
            !res.findings
                .iter()
                .any(|f| f.rule_id == "scan.binary_skipped" || f.rule_id == "scan.non_utf8_lossy"),
            "{:?}",
            res.findings
        );
    }

    #[test]
    fn utf8_bom_does_not_hide_first_line_from_anchored_rules() {
        let root = tempfile::tempdir().unwrap();
        let name = ["API", "TOKEN"].join("_");
        fs::write(
            root.path().join(".env"),
            format!("\u{feff}{name}=abcdefghijklmnop1234\n"),
        )
        .unwrap();
        fs::write(
            root.path().join("key.txt"),
            format!("\u{feff}{}\n", synthetic_openai_key()),
        )
        .unwrap();

        let res = scan_path(root.path(), ScanOptions::default()).unwrap();
        let env_hit = res
            .findings
            .iter()
            .find(|f| f.rule_id == "env.sensitive_assignment")
            .unwrap_or_else(|| panic!("{:?}", res.findings));
        assert_eq!((env_hit.line, env_hit.column), (1, 1));
        let key_hit = res
            .findings
            .iter()
            .find(|f| f.rule_id == "secret.openai_api_key")
            .unwrap_or_else(|| panic!("{:?}", res.findings));
        assert_eq!((key_hit.line, key_hit.column), (1, 1));
    }

    #[test]
    fn context_lines_inside_a_multi_line_match_are_redacted() {
        let mut policy = Policy::default();
        policy.custom_rules.push(CustomRule {
            id: "custom.block".into(),
            pattern: "(?s)START.*?STOP".into(),
            severity: "high".into(),
            kind: "secret".into(),
            message: None,
            confidence: None,
            case_insensitive: false,
            enabled: true,
        });
        // not real personal data: synthetic detector fixture value only
        let content = format!(
            "START alpha\nbravo user@{} charlie\ndelta STOP tail\n",
            "example.com"
        );
        let chunk = scan_text_content("notes.txt", &content, &policy, true).unwrap();
        let email = chunk
            .findings
            .iter()
            .find(|f| f.rule_id == "pii.email")
            .unwrap_or_else(|| panic!("{:?}", chunk.findings));
        assert_eq!(email.context_before, vec!["[REDACTED]".to_string()]);
        assert_eq!(email.context_after, vec!["[REDACTED] tail".to_string()]);
    }
}
