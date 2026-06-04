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
    Ok(build_version_check(current, latest_tag))
}

fn build_version_check(current: &'static str, latest_tag: String) -> VersionCheck {
    let status = compare_versions(current, &latest_tag)
        .map(|ordering| match ordering {
            Ordering::Less => VersionStatus::UpdateAvailable,
            Ordering::Equal => VersionStatus::Current,
            Ordering::Greater => VersionStatus::LocalNewer,
        })
        .unwrap_or(VersionStatus::Unknown);

    VersionCheck {
        current,
        latest_tag,
        status,
    }
}

fn fetch_latest_release_tag() -> Result<String> {
    if let Some(tag) = env_latest_release_tag(env::var(LATEST_RELEASE_TAG_ENV).ok().as_deref()) {
        return Ok(tag);
    }

    let url =
        env::var(LATEST_RELEASE_URL_ENV).unwrap_or_else(|_| LATEST_RELEASE_API_URL.to_string());
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .build()
        .into();
    let body = agent
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", concat!("shk/", env!("CARGO_PKG_VERSION")))
        .call()
        .with_context(|| format!("fetch {url}"))?
        .body_mut()
        .read_to_string()
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

fn env_latest_release_tag(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(ToOwned::to_owned)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_normalizes_prerelease_and_short_forms() {
        assert_eq!(parse_version("v1.2.3"), Some(vec![1, 2, 3]));
        assert_eq!(parse_version("1.2"), Some(vec![1, 2, 0]));
        assert_eq!(parse_version("1.2.3-beta"), Some(vec![1, 2, 3]));
        assert_eq!(parse_version("not-a-version"), None);
    }

    #[test]
    fn compare_versions_orders_semver_parts() {
        assert_eq!(compare_versions("0.3.14", "v0.3.15"), Some(Ordering::Less));
        assert_eq!(compare_versions("1.0.0", "1.0.0"), Some(Ordering::Equal));
        assert_eq!(compare_versions("2.0.0", "1.9.9"), Some(Ordering::Greater));
    }

    #[test]
    fn version_status_maps_to_api_fields() {
        assert_eq!(VersionStatus::Current.as_str(), "current");
        assert_eq!(VersionStatus::LocalNewer.as_str(), "local_newer");
        assert_eq!(
            VersionStatus::UpdateAvailable.update_available(),
            Some(true)
        );
        assert_eq!(VersionStatus::Current.update_available(), Some(false));
        assert_eq!(VersionStatus::LocalNewer.update_available(), Some(false));
        assert_eq!(VersionStatus::Unknown.update_available(), None);
    }

    #[test]
    fn version_check_accessors_expose_expected_fields() {
        let check = build_version_check("1.2.3", "v1.2.4".into());

        assert_eq!(check.current(), "1.2.3");
        assert_eq!(check.latest_tag(), "v1.2.4");
        assert_eq!(check.status().as_str(), "update_available");
        assert_eq!(
            check.release_url(),
            "https://github.com/Kazuki-tam/security-harness-kit/releases/tag/v1.2.4"
        );
    }

    #[test]
    fn build_version_check_reports_current_status() {
        let check = build_version_check(current_version(), current_version().into());
        assert_eq!(check.status().as_str(), "current");
    }

    #[test]
    fn build_version_check_reports_update_available() {
        let check = build_version_check(current_version(), "v999.0.0".into());
        assert_eq!(check.status().as_str(), "update_available");
        assert_eq!(check.status().update_available(), Some(true));
    }

    #[test]
    fn build_version_check_detects_local_newer() {
        let check = build_version_check(current_version(), "v0.0.1".into());
        assert_eq!(check.status().as_str(), "local_newer");
        assert_eq!(check.status().update_available(), Some(false));
    }

    #[test]
    fn env_latest_release_tag_trims_non_empty_override() {
        assert_eq!(
            env_latest_release_tag(Some("  v9.9.9  ")).as_deref(),
            Some("v9.9.9")
        );
        assert_eq!(env_latest_release_tag(Some("   ")), None);
        assert_eq!(env_latest_release_tag(None), None);
    }

    #[test]
    fn release_url_uses_tag_path() {
        assert_eq!(
            release_url("v0.3.14"),
            "https://github.com/Kazuki-tam/security-harness-kit/releases/tag/v0.3.14"
        );
    }
}
