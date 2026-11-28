use sha2::{Digest, Sha256};
use shk_core::finding::Finding;
use shk_deps::DepsFinding;

pub fn report(
    findings: &[Finding],
    run_properties: serde_json::Value,
    include_value_hash: bool,
) -> serde_json::Value {
    let rules = rules(findings);
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|finding| result(finding, include_value_hash))
        .collect();
    document(rules, results, run_properties)
}

/// SARIF for `shk deps audit`. It differs from [`report`] where a dependency
/// finding differs from a scan finding:
///
/// - the rule description is fixed text, as the message names the package;
/// - `deps.vulnerable` becomes one rule per severity
///   (`deps.vulnerable/high`, …), because code scanning takes an alert's
///   severity from its rule, not from the result;
/// - every result carries a fingerprint made from the finding's alert key,
///   so that code scanning keeps one alert while lockfile lines shift;
/// - the advisory details are in `properties.dependency`.
pub fn report_deps(
    findings: &[DepsFinding],
    run_properties: serde_json::Value,
) -> serde_json::Value {
    let mut by_rule = std::collections::BTreeMap::<String, &Finding>::new();
    let mut results = Vec::with_capacity(findings.len());
    for deps_finding in findings {
        let finding = &deps_finding.finding;
        let rule_id = deps_rule_id(finding);
        let mut result = result(finding, false);
        result["ruleId"] = serde_json::json!(rule_id);
        result["partialFingerprints"] = serde_json::json!({
            "primaryLocationLineHash": sha256_hex(&deps_finding.alert_key),
        });
        if let Some(dependency) = &deps_finding.dependency {
            result["properties"]["dependency"] = serde_json::json!(dependency);
        }
        results.push(result);
        by_rule.entry(rule_id).or_insert(finding);
    }
    let rules = by_rule
        .into_iter()
        .map(|(rule_id, finding)| {
            let description = shk_deps::audit::short_description(&finding.rule_id)
                .unwrap_or(finding.message.as_str());
            rule(&rule_id, description, finding)
        })
        .collect();
    document(rules, results, run_properties)
}

fn deps_rule_id(finding: &Finding) -> String {
    if finding.rule_id == "deps.vulnerable" {
        format!("{}/{}", finding.rule_id, finding.severity)
    } else {
        finding.rule_id.clone()
    }
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn document(
    rules: Vec<serde_json::Value>,
    results: Vec<serde_json::Value>,
    run_properties: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "shk",
                        "semanticVersion": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/Kazuki-tam/security-harness-kit",
                        "rules": rules
                    }
                },
                "results": results,
                "properties": run_properties
            }
        ]
    })
}

fn rules(findings: &[Finding]) -> Vec<serde_json::Value> {
    let mut by_rule = std::collections::BTreeMap::<String, &Finding>::new();
    for finding in findings {
        by_rule.entry(finding.rule_id.clone()).or_insert(finding);
    }
    by_rule
        .into_iter()
        .map(|(rule_id, finding)| rule(&rule_id, &finding.message, finding))
        .collect()
}

/// One rule, described by the first finding that uses it.
fn rule(id: &str, description: &str, finding: &Finding) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "name": finding.rule_id,
        "shortDescription": { "text": description },
        "properties": {
            "kind": finding.kind,
            "security-severity": security_severity(&finding.severity),
            "precision": precision(finding.confidence),
            "tags": ["security", finding.kind]
        }
    })
}

fn result(finding: &Finding, include_value_hash: bool) -> serde_json::Value {
    let mut properties = serde_json::json!({
        "severity": finding.severity,
        "kind": finding.kind,
        "confidence": finding.confidence,
        "redactedValue": finding.redacted_value,
    });
    if include_value_hash
        && let Some(hash) = &finding.value_hash
        && let Some(map) = properties.as_object_mut()
    {
        map.insert("valueHash".into(), serde_json::json!(hash));
    }

    serde_json::json!({
        "ruleId": finding.rule_id,
        "level": level(&finding.severity),
        "message": { "text": finding.message },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": { "uri": finding.file },
                    "region": {
                        "startLine": finding.line.max(1),
                        "startColumn": finding.column.max(1)
                    }
                }
            }
        ],
        "properties": properties
    })
}

fn level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" | "info" => "note",
        _ => "warning",
    }
}

fn security_severity(severity: &str) -> &'static str {
    match severity {
        "critical" => "9.0",
        "high" => "8.0",
        "medium" => "5.0",
        "low" => "2.0",
        "info" => "0.0",
        _ => "5.0",
    }
}

fn precision(confidence: f32) -> &'static str {
    if confidence >= 0.85 {
        "high"
    } else if confidence >= 0.6 {
        "medium"
    } else {
        "low"
    }
}
