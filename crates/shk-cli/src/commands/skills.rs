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

pub struct SkillStatus {
    pub label: &'static str,
    pub path: Option<PathBuf>,
    pub installed: bool,
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
    for entry in status_entries() {
        print_status_line(entry.label, entry.path.as_deref());
    }
    Ok(())
}

pub fn status_entries_for(root: &Path) -> Vec<SkillStatus> {
    let tools = [
        ("claude-code (project)", SkillTool::ClaudeCode, false),
        ("claude-code (global)", SkillTool::ClaudeCode, true),
        ("codex/cursor (project)", SkillTool::Codex, false),
        ("codex/cursor (global)", SkillTool::Codex, true),
    ];

    tools
        .into_iter()
        .map(|(label, tool, global)| {
            match resolve_base_for(root, global).and_then(|base| dest_path_for(&base, tool, global))
            {
                Ok(path) => SkillStatus {
                    label,
                    installed: path.exists(),
                    path: Some(path),
                },
                Err(_) => SkillStatus {
                    label,
                    installed: false,
                    path: None,
                },
            }
        })
        .collect()
}

pub fn install_for(root: &Path, args: SkillsInstallArgs) -> Result<Vec<String>> {
    let plans = selected_tools(args.tool.unwrap_or(SkillTool::All))
        .into_iter()
        .map(|tool| {
            let base = resolve_base_for(root, args.global)?;
            Ok(InstallPlan {
                tool,
                dest: dest_path_for(&base, tool, args.global)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    if !args.dry_run && !args.force {
        ensure_no_existing_destinations(&plans)?;
    }

    let mut details = Vec::new();
    for plan in &plans {
        if args.dry_run {
            details.push(format!(
                "[dry-run] would write {} skill to {} ({} bytes)",
                plan.tool.label(),
                plan.dest.display(),
                SKILL_CONTENT.len()
            ));
            continue;
        }

        let parent = plan.dest.parent().expect("destination has parent");
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        std::fs::write(&plan.dest, SKILL_CONTENT)
            .with_context(|| format!("write {}", plan.dest.display()))?;
        details.push(format!(
            "Installed {} skill → {}",
            plan.tool.label(),
            plan.dest.display()
        ));
    }
    Ok(details)
}

pub fn status_entries() -> Vec<SkillStatus> {
    status_entries_for(&std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

fn print_status_line(label: &str, path: Option<&Path>) {
    match path {
        Some(p) if p.exists() => println!("  {label}  installed  ({})", p.display()),
        Some(p) => println!("  {label}  not installed  ({})", p.display()),
        None => println!("  {label}  unavailable"),
    }
}

fn dest_path(tool: SkillTool, global: bool) -> Result<PathBuf> {
    let root = std::env::current_dir().context("current directory")?;
    let base = resolve_base_for(&root, global)?;
    dest_path_for(&base, tool, global)
}

fn resolve_base_for(root: &Path, global: bool) -> Result<PathBuf> {
    if global {
        dirs::home_dir().context("home directory not found")
    } else {
        Ok(root.to_path_buf())
    }
}

fn dest_path_for(base: &Path, tool: SkillTool, _global: bool) -> Result<PathBuf> {
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
