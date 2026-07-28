use crate::args::SeverityArg;
use crate::exit::CliExit;
use crate::mcp_audit;
use anyhow::Result;
use shk_core::policy::Severity;
use std::path::PathBuf;

pub struct McpAuditInvocation {
    pub path: PathBuf,
    pub global: bool,
    pub json: bool,
    pub sarif: bool,
    pub fail_on: Option<SeverityArg>,
    pub verbose: bool,
    pub color_enabled: bool,
}

pub fn run(inv: McpAuditInvocation) -> Result<()> {
    if inv.json && inv.sarif {
        return Err(CliExit::message(2, "`--json` and `--sarif` cannot be used together").into());
    }
    let threshold = inv.fail_on.map(Severity::from).unwrap_or(Severity::High);
    let report = mcp_audit::audit(&inv.path, inv.global, threshold)
        .map_err(|err| CliExit::message(2, format!("MCP audit failed: {err:#}")))?;

    if inv.sarif {
        let sarif = crate::sarif::report(
            &report.findings,
            serde_json::json!({
                "configFiles": report.config_files,
                "servers": report.servers,
                "exitThreshold": report.exit_threshold
            }),
            false,
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&sarif)
                .map_err(|_| CliExit::message(2, "MCP SARIF serialization failed"))?
        );
    } else if inv.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|_| CliExit::message(2, "MCP JSON serialization failed"))?
        );
    } else {
        println!(
            "MCP audit: {} config files, {} servers\n",
            report.config_files.len(),
            report.servers.len()
        );
        let visible: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| inv.verbose || finding.severity != "info")
            .cloned()
            .collect();
        print!(
            "{}",
            crate::output::format_human_findings(&visible, inv.color_enabled, true, 0)
        );
        let counts = &report.summary.by_severity;
        println!(
            "{} critical, {} high, {} medium, {} low, {} info{}",
            counts.get("critical").copied().unwrap_or(0),
            counts.get("high").copied().unwrap_or(0),
            counts.get("medium").copied().unwrap_or(0),
            counts.get("low").copied().unwrap_or(0),
            counts.get("info").copied().unwrap_or(0),
            if !inv.verbose && counts.get("info").copied().unwrap_or(0) > 0 {
                " (use --verbose to show info)"
            } else {
                ""
            }
        );
    }

    if report.should_fail() {
        return Err(CliExit::silent(1).into());
    }
    Ok(())
}
