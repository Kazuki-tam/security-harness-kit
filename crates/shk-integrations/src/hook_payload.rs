//! Shared parsing for AI hook stdin payloads.

use serde_json::Value;

/// Top-level keys that hold a tool's whole argument list. Pre hooks scan every
/// string in them except path arguments that named a file read for the scan
/// and edit pairs (scanned in the edited file instead).
/// - Claude Code, Codex, Cursor, Copilot (VS Code-compatible format), and the
///   OpenCode plugin: `tool_input`
/// - Copilot CLI camelCase `preToolUse` / `postToolUse`: `toolArgs`
/// - Grok Build: `toolInput`
///
/// Some tools send the envelope as a JSON-encoded string instead of an
/// object: Copilot CLI `toolArgs`, Copilot's VS Code-compatible `tool_input`
/// (only parsed upstream "when possible"), and Cursor
/// `beforeMCPExecution` / `afterMCPExecution` `tool_input`.
pub(crate) const ARGUMENT_ENVELOPE_KEYS: &[&str] = &["tool_input", "toolArgs", "toolInput"];

/// Parses hook stdin and decodes stringified argument envelopes in place, so
/// key-based lookups (file paths, shell commands, text keys) see the nested
/// arguments.
pub(crate) fn parse_hook_payload(stdin: &str) -> serde_json::Result<Value> {
    let mut v: Value = serde_json::from_str(stdin)?;
    decode_encoded_arguments(&mut v);
    Ok(v)
}

/// Replaces each top-level envelope string that holds a JSON object or array
/// with the decoded value. Other strings (plain text, scalars) are left as is.
pub(crate) fn decode_encoded_arguments(v: &mut Value) {
    let Some(map) = v.as_object_mut() else {
        return;
    };
    for key in ARGUMENT_ENVELOPE_KEYS {
        let Some(slot) = map.get_mut(*key) else {
            continue;
        };
        let Some(raw) = slot.as_str() else {
            continue;
        };
        if let Ok(decoded @ (Value::Object(_) | Value::Array(_))) = serde_json::from_str(raw) {
            *slot = decoded;
        }
    }
}

/// Copilot CLI camelCase `preToolUse` payload whose `toolArgs` is a
/// JSON-encoded string, for tests across the crate.
#[cfg(test)]
pub(crate) fn copilot_cli_payload(tool: &str, args: Value) -> Value {
    serde_json::json!({
        "timestamp": 1704614400000_u64,
        "cwd": "/work/repo",
        "toolName": tool,
        "toolArgs": args.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decodes_stringified_copilot_tool_args() {
        let stdin = copilot_cli_payload("bash", json!({ "command": "ls" })).to_string();

        let v = parse_hook_payload(&stdin).unwrap();

        assert_eq!(v["toolArgs"]["command"], "ls");
        assert_eq!(v["toolName"], "bash");
    }

    #[test]
    fn decodes_stringified_tool_input() {
        let stdin = json!({
            "tool_name": "mcp_fetch",
            "tool_input": json!({ "url": "https://example.com" }).to_string()
        })
        .to_string();

        let v = parse_hook_payload(&stdin).unwrap();

        assert_eq!(v["tool_input"]["url"], "https://example.com");
    }

    #[test]
    fn leaves_objects_plain_strings_and_nested_envelopes_untouched() {
        let nested = json!({ "command": "ls" }).to_string();
        let stdin = json!({
            "tool_input": { "command": "echo hi" },
            "toolArgs": "not json",
            "outer": { "toolArgs": nested }
        })
        .to_string();

        let v = parse_hook_payload(&stdin).unwrap();

        assert_eq!(v["tool_input"]["command"], "echo hi");
        assert_eq!(v["toolArgs"], "not json");
        assert_eq!(v["outer"]["toolArgs"], nested);
    }

    #[test]
    fn leaves_json_scalars_as_strings() {
        let stdin = json!({ "toolArgs": "42", "tool_input": "\"quoted\"" }).to_string();

        let v = parse_hook_payload(&stdin).unwrap();

        assert_eq!(v["toolArgs"], "42");
        assert_eq!(v["tool_input"], "\"quoted\"");
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(parse_hook_payload("not json").is_err());
    }
}
