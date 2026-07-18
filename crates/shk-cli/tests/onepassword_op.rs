//! Opt-in integration tests against the real 1Password CLI.
//!
//! Run with:
//! `SHK_OP_TEST_VAULT=shk-integration-test cargo test -p shk-cli --test onepassword_op -- --ignored`

use serde::Serialize;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_VAULT_ENV: &str = "SHK_OP_TEST_VAULT";

fn shk_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_shk"))
}

#[derive(Serialize)]
struct TestPolicy<'a> {
    env: TestEnvPolicy<'a>,
}

#[derive(Serialize)]
struct TestEnvPolicy<'a> {
    secret_store: &'static str,
    project_id: &'a str,
    onepassword: TestOnePasswordPolicy<'a>,
}

#[derive(Serialize)]
struct TestOnePasswordPolicy<'a> {
    vault: &'a str,
}

struct OpTestProject {
    dir: tempfile::TempDir,
    vault: String,
    project_id: String,
    op_bin: OsString,
}

impl OpTestProject {
    fn new(label: &str) -> Option<Self> {
        let vault = std::env::var(TEST_VAULT_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        let project_id = format!("shk-op-test/{label}-{}-{nonce}", std::process::id());
        let dir = tempfile::tempdir().expect("create temporary shk project");
        let policy = toml::to_string(&TestPolicy {
            env: TestEnvPolicy {
                secret_store: "1password",
                project_id: &project_id,
                onepassword: TestOnePasswordPolicy { vault: &vault },
            },
        })
        .expect("serialize test shk.toml");
        std::fs::write(dir.path().join("shk.toml"), policy).expect("write test shk.toml");

        Some(Self {
            dir,
            vault,
            project_id,
            op_bin: std::env::var_os("SHK_OP_PATH").unwrap_or_else(|| OsString::from("op")),
        })
    }

    fn run_shk(&self, args: &[&str]) -> Output {
        Command::new(shk_bin())
            .args(args)
            .current_dir(self.dir.path())
            .output()
            .expect("run shk")
    }

    fn run_op(&self, args: &[&str]) -> Output {
        self.try_run_op(args).expect("run 1Password CLI")
    }

    fn try_run_op(&self, args: &[&str]) -> std::io::Result<Output> {
        Command::new(&self.op_bin).args(args).output()
    }

    fn native_title(&self) -> String {
        format!("shk:{}:env:DOTENV_PRIVATE_KEY", self.project_id)
    }

    fn cleanup_items(&self) {
        let Ok(output) =
            self.try_run_op(&["item", "list", "--vault", &self.vault, "--format", "json"])
        else {
            return;
        };
        if !output.status.success() {
            return;
        }
        let Ok(items) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
            return;
        };
        let prefix = format!("shk:{}:", self.project_id);
        let Some(items) = items.as_array() else {
            return;
        };
        for item in items {
            let matches_project = item
                .get("title")
                .and_then(|value| value.as_str())
                .is_some_and(|title| title.starts_with(&prefix));
            if !matches_project {
                continue;
            }
            let Some(id) = item.get("id").and_then(|value| value.as_str()) else {
                continue;
            };
            let _ = self.try_run_op(&["item", "delete", id, "--vault", &self.vault]);
        }
    }
}

impl Drop for OpTestProject {
    fn drop(&mut self) {
        self.cleanup_items();
    }
}

fn assert_success(output: &Output, action: &str) {
    assert!(
        output.status.success(),
        "{action} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires a real 1Password CLI session and SHK_OP_TEST_VAULT"]
fn onepassword_round_trips_an_env_key() {
    let Some(project) = OpTestProject::new("roundtrip") else {
        eprintln!("skipped: {TEST_VAULT_ENV} is not set");
        return;
    };
    let encrypted = project.dir.path().join(".env");
    let decrypted = project.dir.path().join(".env.plain");
    std::fs::write(&encrypted, "APP_TOKEN=integration-value\n").expect("write plaintext env");

    let output = project.run_shk(&["env", "encrypt", ".env", "--in-place"]);
    assert_success(&output, "encrypt through 1Password");
    let encrypted_body = std::fs::read_to_string(&encrypted).expect("read encrypted env");
    assert!(!encrypted_body.contains("APP_TOKEN=integration-value"));

    let output = project.run_shk(&[
        "env",
        "decrypt",
        ".env",
        "--output",
        decrypted.to_str().expect("UTF-8 test path"),
    ]);
    assert_success(&output, "decrypt through 1Password");
    let decrypted_body = std::fs::read_to_string(decrypted).expect("read decrypted env");
    assert!(decrypted_body.contains("APP_TOKEN=\"integration-value\""));
}

#[test]
#[ignore = "requires a real 1Password CLI session and SHK_OP_TEST_VAULT"]
fn onepassword_never_modifies_a_same_title_item_with_only_a_subtag() {
    let Some(project) = OpTestProject::new("subtag") else {
        eprintln!("skipped: {TEST_VAULT_ENV} is not set");
        return;
    };
    let title = project.native_title();
    let output = project.run_op(&[
        "item",
        "create",
        "--category",
        "Password",
        "--title",
        &title,
        "--tags",
        "shk/unmanaged",
        "--vault",
        &project.vault,
        "--format",
        "json",
    ]);
    assert_success(&output, "create same-title item with only a subtag");
    let item: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse created 1Password item");
    let subtag_item_id = item["id"].as_str().expect("created item ID").to_string();

    std::fs::write(
        project.dir.path().join(".env"),
        "APP_TOKEN=integration-value\n",
    )
    .expect("write plaintext env");
    let output = project.run_shk(&["env", "encrypt", ".env", "--in-place"]);
    assert_success(&output, "create managed key beside unmanaged item");
    let output = project.run_shk(&["env", "key", "delete", "--all"]);
    assert_success(&output, "delete managed key");

    let output = project.run_op(&[
        "item",
        "get",
        &subtag_item_id,
        "--vault",
        &project.vault,
        "--format",
        "json",
    ]);
    assert_success(&output, "verify subtag-only item remains");
}
