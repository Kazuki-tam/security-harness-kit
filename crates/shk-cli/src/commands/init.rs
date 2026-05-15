use crate::args::AiTool;
use crate::commands::skills::{SkillTool, SkillsInstallArgs};
use crate::{hooks, npm_hardening, policy_cmd, safety};
use anyhow::Result;
use dialoguer::{Confirm, MultiSelect, Select, theme::ColorfulTheme};
use std::io::{self, IsTerminal, Write};
use std::path::Path;

#[derive(Clone, Debug)]
pub struct InitArgs {
    pub strict: bool,
    pub force: bool,
    pub yes: bool,
    pub audit: bool,
    pub tools: Vec<AiTool>,
    pub no_git_hook: bool,
    pub no_ai_hooks: bool,
    pub no_skills: bool,
    pub no_npm_hardening: bool,
    pub global: bool,
    pub apply_sandbox: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    Default,
    Strict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HookMode {
    Blocking,
    Audit,
}

#[derive(Clone, Copy, Debug)]
struct PromptChoice<T> {
    value: T,
    label: &'static str,
}

const AI_TOOL_CHOICES: &[PromptChoice<AiTool>] = &[
    PromptChoice {
        value: AiTool::ClaudeCode,
        label: "Claude Code",
    },
    PromptChoice {
        value: AiTool::Codex,
        label: "Codex",
    },
    PromptChoice {
        value: AiTool::Cursor,
        label: "Cursor",
    },
];

const PROFILE_CHOICES: &[PromptChoice<Profile>] = &[
    PromptChoice {
        value: Profile::Default,
        label: "Default  (recommended for most projects)",
    },
    PromptChoice {
        value: Profile::Strict,
        label: "Strict   (fails on medium-severity findings)",
    },
];

const HOOK_MODE_CHOICES: &[PromptChoice<HookMode>] = &[
    PromptChoice {
        value: HookMode::Blocking,
        label: "Blocking  (stops on findings)",
    },
    PromptChoice {
        value: HookMode::Audit,
        label: "Audit     (log only, never blocks)",
    },
];

pub fn run(cwd: &Path, args: InitArgs) -> Result<()> {
    if should_run_legacy_policy_init(&args) {
        return policy_cmd::init(cwd, args.strict, args.force);
    }

    println!("shk init");
    let mut prompt = Prompt::new(args.yes);
    let profile = if args.strict {
        Profile::Strict
    } else {
        prompt.profile("Policy profile", Profile::Default)?
    };
    let strict = profile == Profile::Strict;
    let policy_path = cwd.join("shk.toml");
    let create_policy = if policy_path.exists() {
        args.force || prompt.confirm("shk.toml already exists. Overwrite it?", false)?
    } else {
        prompt.confirm("Create shk.toml?", true)?
    };

    if create_policy {
        policy_cmd::init(cwd, strict, args.force || policy_path.exists())?;
    } else {
        println!("Skipped shk.toml");
    }

    let npm_status = npm_hardening::status(cwd);
    if args.no_npm_hardening {
        if npm_status.has_npm_projects() {
            println!("Skipped npm supply-chain hardening");
        }
    } else if npm_status.has_npm_projects() && {
        println!(
            "Note: ignore-scripts=true may break packages that require native compilation (e.g. sharp, bcrypt). Verify after applying."
        );
        prompt.confirm("Apply npm supply-chain hardening?", true)?
    }
    {
        for path in npm_status.apply_paths() {
            safety::ensure_writable_path_allowed(path)?;
        }
        if let Some(status) = npm_hardening::apply(cwd)? {
            println!(
                "Applied package manager hardening ({} package.json file(s), manager(s): {})",
                status.package_dirs.len(),
                status
                    .package_managers
                    .iter()
                    .map(|manager| manager.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    } else if npm_status.has_npm_projects() {
        println!("Skipped npm supply-chain hardening");
    }

    let repo_root = shk_core::git::discover_repo_root(cwd);
    if !args.no_git_hook {
        match repo_root.as_deref() {
            Some(root) if prompt.confirm("Install Git pre-commit hook?", true)? => {
                safety::require_project_policy(cwd, "init git hook setup")?;
                hooks::install_pre_commit(root)?;
                println!("Installed pre-commit hook under {}", root.display());
            }
            Some(_) => println!("Skipped Git pre-commit hook"),
            None => println!("Skipped Git pre-commit hook (not a Git repository)"),
        }
    }

    let tools = resolve_tools(&mut prompt, &args)?;
    let install_ai_hooks = !args.no_ai_hooks
        && !tools.is_empty()
        && prompt.confirm("Install AI editor hooks?", true)?;
    if install_ai_hooks {
        safety::require_project_policy(cwd, "init AI hook setup")?;
        let mode = if args.audit {
            HookMode::Audit
        } else {
            prompt.hook_mode("AI hook mode", HookMode::Blocking)?
        };
        for tool in &tools {
            hooks::install_ai(
                cwd,
                Some(*tool),
                hooks::InstallAiOptions {
                    audit: mode == HookMode::Audit,
                    dry_run: false,
                    global: args.global,
                    fail_closed: args.apply_sandbox,
                    apply_deny: false,
                    apply_sandbox: args.apply_sandbox,
                },
            )?;
        }
    } else if args.no_ai_hooks {
        println!("Skipped AI editor hooks");
    }

    let install_skills = !args.no_skills
        && !tools.is_empty()
        && prompt.confirm("Install bundled agent skill?", true)?;
    if install_skills {
        crate::commands::skills::install(SkillsInstallArgs {
            tool: Some(skill_tool_for(&tools)),
            global: args.global,
            dry_run: false,
            force: args.force,
        })?;
    } else if args.no_skills {
        println!("Skipped agent skills");
    }

    println!("Done. Run `shk status` to check the setup.");
    Ok(())
}

fn should_run_legacy_policy_init(args: &InitArgs) -> bool {
    !args.yes
        && !io::stdin().is_terminal()
        && args.tools.is_empty()
        && !args.audit
        && !args.no_git_hook
        && !args.no_ai_hooks
        && !args.no_skills
        && !args.no_npm_hardening
        && !args.global
        && !args.apply_sandbox
}

fn resolve_tools(prompt: &mut Prompt, args: &InitArgs) -> Result<Vec<AiTool>> {
    if !args.tools.is_empty() {
        return Ok(dedupe_tools(&args.tools));
    }
    if args.yes {
        return Ok(vec![AiTool::ClaudeCode, AiTool::Codex, AiTool::Cursor]);
    }
    prompt.tools(
        "AI tools",
        &[AiTool::ClaudeCode, AiTool::Codex, AiTool::Cursor],
    )
}

fn dedupe_tools(tools: &[AiTool]) -> Vec<AiTool> {
    dedupe_values(tools)
}

fn skill_tool_for(tools: &[AiTool]) -> SkillTool {
    let has_claude = tools.contains(&AiTool::ClaudeCode);
    let has_agent_skill = tools
        .iter()
        .any(|tool| matches!(tool, AiTool::Codex | AiTool::Cursor));

    match (has_claude, has_agent_skill) {
        (true, true) => SkillTool::All,
        (true, false) => SkillTool::ClaudeCode,
        (false, true) => {
            if tools.contains(&AiTool::Cursor) && !tools.contains(&AiTool::Codex) {
                SkillTool::Cursor
            } else {
                SkillTool::Codex
            }
        }
        (false, false) => unreachable!("skill installation requires at least one tool"),
    }
}

struct Prompt {
    yes: bool,
    rich: bool,
    theme: ColorfulTheme,
}

impl Prompt {
    fn new(yes: bool) -> Self {
        Self {
            yes,
            rich: io::stdin().is_terminal() && io::stdout().is_terminal(),
            theme: ColorfulTheme::default(),
        }
    }

    fn confirm(&mut self, label: &str, default: bool) -> Result<bool> {
        if self.yes {
            return Ok(default);
        }
        if self.rich {
            return Ok(Confirm::with_theme(&self.theme)
                .with_prompt(label)
                .default(default)
                .interact()?);
        }
        loop {
            print!("{label} {} ", if default { "[Y/n]" } else { "[y/N]" });
            io::stdout().flush()?;
            let input = read_line()?;
            let trimmed = input.trim().to_ascii_lowercase();
            if trimmed.is_empty() {
                return Ok(default);
            }
            match trimmed.as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => println!("Please answer y or n."),
            }
        }
    }

    fn profile(&mut self, label: &str, default: Profile) -> Result<Profile> {
        if self.yes {
            return Ok(default);
        }
        if self.rich {
            return self.select_choice(label, PROFILE_CHOICES, default);
        }
        loop {
            print!("{label} [default/strict] ({}) ", profile_label(default));
            io::stdout().flush()?;
            let input = read_line()?;
            let trimmed = input.trim().to_ascii_lowercase();
            if trimmed.is_empty() {
                return Ok(default);
            }
            match trimmed.as_str() {
                "default" | "d" => return Ok(Profile::Default),
                "strict" | "s" => return Ok(Profile::Strict),
                _ => println!("Choose default or strict."),
            }
        }
    }

    fn hook_mode(&mut self, label: &str, default: HookMode) -> Result<HookMode> {
        if self.yes {
            return Ok(default);
        }
        if self.rich {
            return self.select_choice(label, HOOK_MODE_CHOICES, default);
        }
        loop {
            print!("{label} [block/audit] ({}) ", hook_mode_label(default));
            io::stdout().flush()?;
            let input = read_line()?;
            let trimmed = input.trim().to_ascii_lowercase();
            if trimmed.is_empty() {
                return Ok(default);
            }
            match trimmed.as_str() {
                "block" | "blocking" | "b" => return Ok(HookMode::Blocking),
                "audit" | "a" => return Ok(HookMode::Audit),
                _ => println!("Choose block or audit."),
            }
        }
    }

    fn tools(&mut self, label: &str, default: &[AiTool]) -> Result<Vec<AiTool>> {
        self.multi_select(label, AI_TOOL_CHOICES, default)
    }

    fn select_choice<T: Copy + PartialEq>(
        &mut self,
        label: &str,
        choices: &[PromptChoice<T>],
        default: T,
    ) -> Result<T> {
        if self.yes {
            return Ok(default);
        }
        let labels: Vec<&str> = choices.iter().map(|choice| choice.label).collect();
        let default_idx = choices
            .iter()
            .position(|choice| choice.value == default)
            .unwrap_or(0);
        let selected = Select::with_theme(&self.theme)
            .with_prompt(label)
            .items(&labels)
            .default(default_idx)
            .interact()?;
        Ok(choices[selected].value)
    }

    fn multi_select<T: Copy + PartialEq>(
        &mut self,
        label: &str,
        choices: &[PromptChoice<T>],
        default: &[T],
    ) -> Result<Vec<T>> {
        if self.yes {
            return Ok(default.to_vec());
        }
        if self.rich {
            let labels: Vec<&str> = choices.iter().map(|choice| choice.label).collect();
            let defaults: Vec<bool> = choices
                .iter()
                .map(|choice| default.contains(&choice.value))
                .collect();
            loop {
                let selected = MultiSelect::with_theme(&self.theme)
                    .with_prompt(label)
                    .items(&labels)
                    .defaults(&defaults)
                    .interact()?;
                if !selected.is_empty() {
                    let values: Vec<T> =
                        selected.into_iter().map(|idx| choices[idx].value).collect();
                    return Ok(dedupe_values(&values));
                }
                println!("Choose at least one option.");
            }
        }
        print_choices(label, choices);
        'prompt: loop {
            print!("Select numbers (comma-separated), or press Enter for all: ");
            io::stdout().flush()?;
            let input = read_line()?;
            let trimmed = input.trim();
            if trimmed.is_empty() || trimmed == "0" {
                return Ok(default.to_vec());
            }
            let mut tools = Vec::new();
            for part in trimmed.split(',') {
                let raw = part.trim();
                if raw == "0" {
                    return Ok(default.to_vec());
                }
                match raw.parse::<usize>() {
                    Ok(n) if n >= 1 && n <= choices.len() => tools.push(choices[n - 1].value),
                    _ => {
                        println!(
                            "Invalid choice `{raw}`. Enter numbers 0-{} separated by commas.",
                            choices.len()
                        );
                        continue 'prompt;
                    }
                }
            }
            let selected = dedupe_values(&tools);
            if !selected.is_empty() {
                return Ok(selected);
            }
            println!("Choose at least one option, or 0 for all.");
        }
    }
}

fn print_choices<T>(label: &str, choices: &[PromptChoice<T>]) {
    println!("{label}:");
    println!("  0) All (default)");
    for (i, choice) in choices.iter().enumerate() {
        println!("  {}) {}", i + 1, choice.label);
    }
}

fn dedupe_values<T: Copy + PartialEq>(values: &[T]) -> Vec<T> {
    let mut out = Vec::new();
    for value in values {
        if !out.contains(value) {
            out.push(*value);
        }
    }
    out
}

fn read_line() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input)
}

fn profile_label(profile: Profile) -> &'static str {
    match profile {
        Profile::Default => "default",
        Profile::Strict => "strict",
    }
}

fn hook_mode_label(mode: HookMode) -> &'static str {
    match mode {
        HookMode::Blocking => "block",
        HookMode::Audit => "audit",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupes_tools_without_reordering() {
        let tools = dedupe_tools(&[AiTool::Codex, AiTool::Cursor, AiTool::Codex]);

        assert_eq!(tools, vec![AiTool::Codex, AiTool::Cursor]);
    }

    #[test]
    fn maps_mixed_tools_to_all_skill_install() {
        assert_eq!(
            skill_tool_for(&[AiTool::ClaudeCode, AiTool::Cursor]),
            SkillTool::All
        );
        assert_eq!(skill_tool_for(&[AiTool::Cursor]), SkillTool::Cursor);
    }
}
