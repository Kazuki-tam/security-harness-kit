use shk_core::finding::Finding;

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
        .map(|(rule_id, finding)| {
            serde_json::json!({
                "id": rule_id,
                "name": finding.rule_id,
                "shortDescription": { "text": finding.message },
                "properties": {
                    "kind": finding.kind,
                    "security-severity": security_severity(&finding.severity),
                    "precision": precision(finding.confidence),
                    "tags": ["security", finding.kind]
                }
            })
        })
        .collect()
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
