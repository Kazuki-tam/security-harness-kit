use anyhow::{Context, Result};
use serde_json::Value;
use std::cmp::Ordering;
use std::env;
use std::time::Duration;

const LATEST_RELEASE_API_URL: &str =
    "https://api.github.com/repos/Kazuki-tam/security-harness-kit/releases/latest";
const LATEST_RELEASE_TAG_ENV: &str = "SHK_UPDATE_CHECK_LATEST_TAG";
const LATEST_RELEASE_URL_ENV: &str = "SHK_UPDATE_CHECK_URL";

#[derive(Clone, Copy)]
pub(crate) enum VersionStatus {
    Current,
    UpdateAvailable,
    LocalNewer,
    Unknown,
}

impl VersionStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::UpdateAvailable => "update_available",
            Self::LocalNewer => "local_newer",
            Self::Unknown => "unknown",
        }
    }

    pub(crate) fn update_available(self) -> Option<bool> {
        match self {
            Self::Current | Self::LocalNewer => Some(false),
            Self::UpdateAvailable => Some(true),
            Self::Unknown => None,
        }
    }
}

pub(crate) struct VersionCheck {
    current: &'static str,
    latest_tag: String,
    status: VersionStatus,
}

impl VersionCheck {
    pub(crate) fn current(&self) -> &'static str {
        self.current
    }

    pub(crate) fn latest_tag(&self) -> &str {
        &self.latest_tag
    }

    pub(crate) fn status(&self) -> VersionStatus {
        self.status
    }

    pub(crate) fn release_url(&self) -> String {
        release_url(&self.latest_tag)
    }
}

pub fn run(json: bool) -> Result<()> {
    match check_latest_version() {
        Ok(check) => {
            if json {
                let v = serde_json::json!({
                    "current": check.current,
                    "latest": check.latest_tag,
                    "status": check.status.as_str(),
                    "update_available": check.status.update_available(),
                    "release_url": release_url(&check.latest_tag),
                });
                println!("{}", serde_json::to_string_pretty(&v)?);
                return Ok(());
            }

            print_human(&check);
        }
        Err(err) => {
            if json {
                let v = serde_json::json!({
                    "current": current_version(),
                    "latest": null,
                    "status": "unknown",
                    "update_available": null,
                    "error": err.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                println!("version: unknown (could not check latest release: {err})");
            }
        }
    }
    Ok(())
}

fn print_human(check: &VersionCheck) {
    match check.status {
        VersionStatus::Current => {
            println!("version: OK ({} is the latest release)", check.current);
        }
        VersionStatus::UpdateAvailable => {
            println!("version: update available");
            println!("  current: {}", check.current);
            println!("  latest:  {}", check.latest_tag);
            println!("  update:  rerun the install script or use your package manager");
            println!("  release: {}", release_url(&check.latest_tag));
        }
        VersionStatus::LocalNewer => {
            println!(
                "version: local version {} is newer than latest release {}",
                check.current, check.latest_tag
            );
        }
        VersionStatus::Unknown => {
            println!("version: latest release differs from local version");
            println!("  current: {}", check.current);
            println!("  latest:  {}", check.latest_tag);
            println!("  release: {}", release_url(&check.latest_tag));
        }
    }
}

pub(crate) fn check_latest_version() -> Result<VersionCheck> {
    let current = current_version();
    let latest_tag = fetch_latest_release_tag()?;
    let status = compare_versions(current, &latest_tag)
        .map(|ordering| match ordering {
            Ordering::Less => VersionStatus::UpdateAvailable,
            Ordering::Equal => VersionStatus::Current,
            Ordering::Greater => VersionStatus::LocalNewer,
        })
        .unwrap_or(VersionStatus::Unknown);

    Ok(VersionCheck {
        current,
        latest_tag,
        status,
    })
}

fn fetch_latest_release_tag() -> Result<String> {
    if let Ok(tag) = env::var(LATEST_RELEASE_TAG_ENV)
        && !tag.trim().is_empty()
    {
        return Ok(tag.trim().to_string());
    }

    let url =
        env::var(LATEST_RELEASE_URL_ENV).unwrap_or_else(|_| LATEST_RELEASE_API_URL.to_string());
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .build();
    let response = agent
        .get(&url)
        .set("Accept", "application/vnd.github+json")
        .set("User-Agent", concat!("shk/", env!("CARGO_PKG_VERSION")))
        .call()
        .with_context(|| format!("fetch {url}"))?;
    let body = response
        .into_string()
        .context("read latest release response")?;
    let value: Value = serde_json::from_str(&body).context("parse latest release response")?;
    value
        .get("tag_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(ToOwned::to_owned)
        .context("latest release response did not include tag_name")
}

fn compare_versions(current: &str, latest_tag: &str) -> Option<Ordering> {
    let current = parse_version(current)?;
    let latest = parse_version(latest_tag)?;
    Some(current.cmp(&latest))
}

fn parse_version(input: &str) -> Option<Vec<u64>> {
    let core = input
        .trim()
        .trim_start_matches('v')
        .split(['-', '+'])
        .next()?;
    let mut parts = core
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if parts.is_empty() {
        return None;
    }
    while parts.len() < 3 {
        parts.push(0);
    }
    Some(parts)
}

fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn release_url(tag: &str) -> String {
    format!("https://github.com/Kazuki-tam/security-harness-kit/releases/tag/{tag}")
}
