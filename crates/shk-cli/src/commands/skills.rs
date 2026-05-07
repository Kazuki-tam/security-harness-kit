use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

const SKILL_NAME: &str = "shk";
const SKILL_CONTENT: &str = include_str!("../skills/shk.md");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkillTool {
    ClaudeCode,
    Codex,
    Cursor,
    All,
}

pub struct SkillsInstallArgs {
    pub tool: Option<SkillTool>,
    pub global: bool,
    pub dry_run: bool,
    pub force: bool,
}

struct InstallPlan {
    tool: SkillTool,
    dest: PathBuf,
}

pub fn install(args: SkillsInstallArgs) -> Result<()> {
    let plans = selected_tools(args.tool.unwrap_or(SkillTool::All))
        .into_iter()
        .map(|tool| {
            Ok(InstallPlan {
                tool,
                dest: dest_path(tool, args.global)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    if !args.dry_run && !args.force {
        ensure_no_existing_destinations(&plans)?;
    }

    for plan in &plans {
        install_plan(plan, args.dry_run)?;
    }

    Ok(())
}

fn selected_tools(tool: SkillTool) -> Vec<SkillTool> {
    match tool {
        // Codex and Cursor both use the open agent skills directory today, so
        // installing for Codex also makes the embedded skill available to Cursor.
        SkillTool::All => vec![SkillTool::ClaudeCode, SkillTool::Codex],
        t => vec![t],
    }
}

fn ensure_no_existing_destinations(plans: &[InstallPlan]) -> Result<()> {
    if let Some(plan) = plans.iter().find(|plan| plan.dest.exists()) {
        bail!(
            "{} already exists — use --force to overwrite",
            plan.dest.display()
        );
    }
    Ok(())
}

fn install_plan(plan: &InstallPlan, dry_run: bool) -> Result<()> {
    if dry_run {
        println!(
            "[dry-run] would write {} skill to {} ({} bytes)",
            plan.tool.label(),
            plan.dest.display(),
            SKILL_CONTENT.len()
        );
        return Ok(());
    }

    let parent = plan.dest.parent().expect("destination has parent");
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    std::fs::write(&plan.dest, SKILL_CONTENT)
        .with_context(|| format!("write {}", plan.dest.display()))?;

    println!(
        "Installed {} skill → {}",
        plan.tool.label(),
        plan.dest.display()
    );
    Ok(())
}

pub fn list() -> Result<()> {
    println!("Available skills:");
    println!("  {SKILL_NAME}  ({} bytes embedded)", SKILL_CONTENT.len());
    Ok(())
}

pub fn status() -> Result<()> {
    println!("shk skill status:");

    let tools = [
        ("claude-code (project)", SkillTool::ClaudeCode, false),
        ("claude-code (global)", SkillTool::ClaudeCode, true),
        ("codex/cursor (project)", SkillTool::Codex, false),
        ("codex/cursor (global)", SkillTool::Codex, true),
    ];

    for (label, tool, global) in &tools {
        match dest_path(*tool, *global) {
            Ok(p) => print_status_line(label, Some(&p)),
            Err(_) => print_status_line(label, None),
        }
    }
    Ok(())
}

fn print_status_line(label: &str, path: Option<&Path>) {
    match path {
        Some(p) if p.exists() => println!("  {label}  installed  ({})", p.display()),
        Some(p) => println!("  {label}  not installed  ({})", p.display()),
        None => println!("  {label}  unavailable"),
    }
}

fn dest_path(tool: SkillTool, global: bool) -> Result<PathBuf> {
    let base = resolve_base(global)?;
    Ok(match tool {
        SkillTool::ClaudeCode => base
            .join(".claude")
            .join("skills")
            .join(format!("{SKILL_NAME}.md")),
        SkillTool::Codex | SkillTool::Cursor => base
            .join(".agents")
            .join("skills")
            .join(SKILL_NAME)
            .join("SKILL.md"),
        SkillTool::All => unreachable!("All is resolved before dest_path"),
    })
}

impl SkillTool {
    fn label(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex/cursor",
            Self::Cursor => "cursor",
            Self::All => "all",
        }
    }
}

fn resolve_base(global: bool) -> Result<PathBuf> {
    if global {
        dirs::home_dir().context("home directory not found")
    } else {
        std::env::current_dir().context("current directory")
    }
}
