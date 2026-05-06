use crate::custom_rules;
use crate::finding::{Finding, ScanJsonReport, ScanSummary};
use crate::git;
use crate::policy::{ColorMode, Policy, Severity};
use crate::suppression;
use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub struct ScanOptions {
    pub staged: bool,
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
            color_mode: match color_mode {
                ColorMode::Auto => "auto".into(),
                ColorMode::Always => "always".into(),
                ColorMode::Never => "never".into(),
            },
        }
    }
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
    if includes.is_empty() || includes.iter().any(|g| g == "**/*") {
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
            exclude: build_exclude_set(&policy.scan.exclude)?,
            include: build_include_set(&policy.scan.include)?,
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

#[cfg(test)]
fn scan_text_content(
    rel: &str,
    content: &str,
    policy: &Policy,
    include_context: bool,
) -> Result<(Vec<Finding>, u64)> {
    let prepared = PreparedScan::new(policy)?;
    scan_text_prepared(rel, content, &prepared, include_context)
}

fn scan_text_prepared(
    rel: &str,
    content: &str,
    prepared: &PreparedScan<'_>,
    include_context: bool,
) -> Result<(Vec<Finding>, u64)> {
    let inline = suppression::parse_inline_suppressions(content);
    let mut suppressed = 0u64;
    let mut findings = Vec::new();

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
    Ok((findings, suppressed))
}

fn scan_one_path(
    root: &Path,
    rel_path: &Path,
    prepared: &PreparedScan<'_>,
    include_context: bool,
) -> Result<(Vec<Finding>, u64)> {
    let full = root.join(rel_path);
    let meta = match fs::metadata(&full) {
        Ok(m) => m,
        Err(_) => return Ok((vec![], 0)),
    };
    if meta.is_dir() {
        return Ok((vec![], 0));
    }
    let rel = rel_normalized(&full, root);
    if meta.len() > prepared.policy.scan.max_file_size_bytes {
        let f = vec![Finding {
            rule_id: "scan.file_too_large".into(),
            severity: "info".into(),
            kind: "ignore".into(),
            file: rel,
            line: 1,
            column: 1,
            message: format!(
                "Skipped: file exceeds max_file_size_bytes ({})",
                prepared.policy.scan.max_file_size_bytes
            ),
            redacted_value: "[REDACTED]".into(),
            confidence: 1.0,
            context_before: vec![],
            context_after: vec![],
        }];
        return Ok((f, 0));
    }
    let mut bytes = fs::read(&full).with_context(|| format!("read {}", full.display()))?;
    let take = prepared.policy.scan.binary_detection_bytes.min(bytes.len());
    if !prepared.policy.scan.include_binary && is_probably_binary(&bytes[..take]) {
        let f = vec![Finding {
            rule_id: "scan.binary_skipped".into(),
            severity: "info".into(),
            kind: "ignore".into(),
            file: rel,
            line: 1,
            column: 1,
            message: "Skipped: binary file (null byte in head)".into(),
            redacted_value: "[REDACTED]".into(),
            confidence: 1.0,
            context_before: vec![],
            context_after: vec![],
        }];
        bytes.zeroize();
        return Ok((f, 0));
    }
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    let result = scan_text_prepared(&rel, &text, prepared, include_context);
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

    let mut suppressed_total = 0u64;
    let expired = suppression::expired_allowlist_warnings(&policy.allowlist);
    let prepared = PreparedScan::new(&policy)?;
    let (scan_findings, suppressed) =
        scan_text_prepared(rel_display_path, content, &prepared, include_context)?;
    suppressed_total += suppressed;
    let findings = prepend_policy_warnings(expired, scan_findings);
    drop(prepared);

    Ok(ScanResult {
        findings,
        scanned_paths: vec![rel_display_path.to_string()],
        policy,
        policy_path,
        exit_threshold,
        suppressed: suppressed_total,
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
    let mut scanned = Vec::new();
    let mut suppressed_total = 0u64;
    for rel in paths {
        scanned.push(rel.to_string_lossy().replace('\\', "/"));
        let (f, sup) = scan_one_path(&repo, &rel, &prepared, include_context)?;
        findings.extend(f);
        suppressed_total += sup;
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
    })
}

pub fn scan_path(target: &Path, opts: ScanOptions) -> Result<ScanResult> {
    if opts.staged {
        return scan_staged(target, opts);
    }

    let root = if target.is_dir() {
        target.to_path_buf()
    } else {
        target
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    let root = fs::canonicalize(&root).unwrap_or(root);
    let (mut policy, policy_path) = Policy::load_from_dir(&root)?;
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
    let expired = suppression::expired_allowlist_warnings(&policy.allowlist);
    let prepared = PreparedScan::new(&policy)?;

    if target.is_file() {
        let abs_target = fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
        let rel = abs_target
            .strip_prefix(&root)
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
            });
        }
        let (scan_findings, sup) = scan_one_path(&root, &rel, &prepared, include_context)?;
        suppressed_total += sup;
        let findings = prepend_policy_warnings(expired, scan_findings);
        drop(prepared);
        return Ok(ScanResult {
            findings,
            scanned_paths: vec![rel_s],
            policy,
            policy_path,
            exit_threshold,
            suppressed: suppressed_total,
        });
    }

    let mut walk = WalkBuilder::new(&root);
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
            let rel = rel_normalized(full, &root);
            filters.allows(&rel)
        })
        .collect();

    let chunk_results: Vec<Result<(Vec<Finding>, u64)>> = scanned_files
        .par_iter()
        .map(|full| {
            let rel = full.strip_prefix(&root).unwrap_or(full).to_path_buf();
            scan_one_path(&root, &rel, &prepared, include_context)
        })
        .collect();

    let mut findings = expired;
    for chunk in chunk_results {
        let (f, s) = chunk?;
        findings.extend(f);
        suppressed_total += s;
    }

    let scanned_paths: Vec<String> = scanned_files
        .iter()
        .map(|p| rel_normalized(p, &root))
        .collect();
    drop(prepared);

    Ok(ScanResult {
        findings,
        scanned_paths,
        policy,
        policy_path,
        exit_threshold,
        suppressed: suppressed_total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AllowlistEntry, CustomRule, Policy};

    #[test]
    fn path_filters_include_glob() {
        let mut p = Policy::default();
        p.scan.include = vec!["**/only-me.txt".into()];
        p.scan.exclude = vec![];
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
        let (f, suppressed) = scan_text_content("w.txt", text, &p, false).unwrap();
        assert!(suppressed >= 1, "expect suppression: findings={f:?}");
        assert!(
            !f.iter().any(|x| x.rule_id == "secret.openai_api_key"),
            "{f:?}"
        );
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

        let (findings, suppressed) =
            scan_text_content("notes.txt", "launch ProjectNebula\n", &p, true).unwrap();

        assert_eq!(suppressed, 0);
        let f = findings
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

        let (findings, suppressed) =
            scan_text_content("notes.txt", "launch ProjectNebula\n", &p, false).unwrap();

        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(suppressed, 0);
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

        let (findings, suppressed) =
            scan_text_content("docs/roadmap.md", "ProjectNebula\n", &p, false).unwrap();

        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(suppressed, 1);
    }
}
