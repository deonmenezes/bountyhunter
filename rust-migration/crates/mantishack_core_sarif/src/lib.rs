//! SARIF result/rule transforms — Rust port of the pure functions in
//! `core/sarif/parser.py`.
//!
//! Covered: `_extract_cwe_from_rule`, `_result_key`, `deduplicate_findings`,
//! `get_tool_name`, `get_rules`, `sanitize_finding_for_display`. The file-I/O
//! loaders (`load_sarif`, `parse_sarif_findings`, `merge_sarif`) and the
//! `escape_nonprintable`-dependent `extract_dataflow_path` stay call-site in
//! Python and drive these on already-loaded SARIF `Value`s.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

pub mod dataflow;
pub use dataflow::extract_dataflow_path;

/// `cwe[-_]?(\d+)` (case-insensitive) — the CWE-id extraction regex.
fn cwe_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)cwe[-_]?(\d+)").unwrap())
}

fn cwe_from_str(s: &str) -> Option<String> {
    cwe_tag_re().captures(s).map(|c| format!("CWE-{}", &c[1]))
}

/// Python truthiness for a JSON value (used for the `a or b` fallbacks).
fn json_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Extract a CWE ID from a SARIF rule (`_extract_cwe_from_rule`). Inspects
/// `properties.cwe`/`cwe_id` (string or list), `properties.tags`, and
/// `relationships[].target` (id or bare-number + CWE toolComponent). Returns the
/// first CWE found in inspection order.
pub fn extract_cwe_from_rule(rule: &Value) -> Option<String> {
    let empty = Value::Object(Map::new());
    let props = rule.get("properties").filter(|v| v.is_object()).unwrap_or(&empty);

    // `properties.cwe` or `properties.cwe_id` (Python `or`).
    let raw_cwe = props
        .get("cwe")
        .filter(|v| json_truthy(v))
        .or_else(|| props.get("cwe_id"));
    if let Some(raw) = raw_cwe {
        if let Some(s) = raw.as_str() {
            if let Some(cwe) = cwe_from_str(s) {
                return Some(cwe);
            }
        } else if let Some(arr) = raw.as_array() {
            for entry in arr {
                if let Some(s) = entry.as_str() {
                    if let Some(cwe) = cwe_from_str(s) {
                        return Some(cwe);
                    }
                }
            }
        }
    }

    // `properties.tags` — list of strings.
    if let Some(tags) = props.get("tags").and_then(Value::as_array) {
        for tag in tags {
            if let Some(s) = tag.as_str() {
                if let Some(cwe) = cwe_from_str(s) {
                    return Some(cwe);
                }
            }
        }
    }

    // `relationships[].target` — SARIF's canonical CWE linkage.
    if let Some(rels) = rule.get("relationships").and_then(Value::as_array) {
        for rel in rels {
            let Some(target) = rel.get("target").filter(|v| v.is_object()) else { continue };
            let target_id = target.get("id");
            if let Some(s) = target_id.and_then(Value::as_str) {
                if let Some(cwe) = cwe_from_str(s) {
                    return Some(cwe);
                }
            }
            // CodeQL: bare numeric id + toolComponent naming the CWE catalog.
            let tc_is_cwe = target
                .get("toolComponent")
                .and_then(Value::as_object)
                .and_then(|tc| tc.get("name"))
                .and_then(Value::as_str)
                .map(|n| n.to_uppercase() == "CWE")
                .unwrap_or(false);
            if tc_is_cwe {
                if let Some(id) = target_id {
                    if let Some(s) = id.as_str() {
                        if let Ok(n) = s.parse::<i64>() {
                            return Some(format!("CWE-{n}"));
                        }
                    } else if let Some(n) = id.as_i64() {
                        return Some(format!("CWE-{n}"));
                    }
                }
            }
        }
    }

    None
}

/// A SARIF result dedup key (`_result_key`):
/// (ruleId, uri, startLine, endLine, startColumn, fingerprint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultKey {
    pub rule_id: String,
    pub uri: String,
    pub line: i64,
    pub end_line: i64,
    pub start_col: i64,
    pub fingerprint: String,
}

/// Build the extended dedup key for a SARIF result (`_result_key`).
pub fn result_key(result: &Value) -> ResultKey {
    let rule_id = result.get("ruleId").and_then(Value::as_str).unwrap_or("").to_string();
    let empty = Value::Object(Map::new());
    // locs = result.get("locations") or [{}]; phys = locs[0].physicalLocation or {}
    let phys = result
        .get("locations")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|l| l.get("physicalLocation"))
        .filter(|v| v.is_object())
        .unwrap_or(&empty);
    let uri = phys
        .get("artifactLocation")
        .and_then(|a| a.get("uri"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let region = phys.get("region").filter(|v| v.is_object()).unwrap_or(&empty);
    let line = region.get("startLine").and_then(Value::as_i64).unwrap_or(0);
    let end_line = region.get("endLine").and_then(Value::as_i64).unwrap_or(line);
    let start_col = region.get("startColumn").and_then(Value::as_i64).unwrap_or(0);

    let fp = result.get("partialFingerprints").filter(|v| v.is_object());
    let fingerprint = match fp {
        Some(fp) => {
            let hash = fp.get("primaryLocationLineHash").and_then(Value::as_str).unwrap_or("");
            if !hash.is_empty() {
                hash.to_string()
            } else if json_truthy(fp) {
                repr_sorted_items(fp.as_object().unwrap())
            } else {
                String::new()
            }
        }
        None => String::new(),
    };

    ResultKey { rule_id, uri, line, end_line, start_col, fingerprint }
}

/// `repr(sorted(fp.items()))` for the fingerprint fallback.
fn repr_sorted_items(fp: &Map<String, Value>) -> String {
    let mut items: Vec<(&String, &Value)> = fp.iter().collect();
    items.sort_by(|a, b| a.0.cmp(b.0));
    let parts: Vec<String> = items
        .iter()
        .map(|(k, v)| format!("({}, {})", py_repr_str(k), py_repr_value(v)))
        .collect();
    format!("[{}]", parts.join(", "))
}

/// Remove duplicate findings by the (file, startLine, endLine, rule_id)
/// fingerprint, keeping the first (`deduplicate_findings`).
pub fn deduplicate_findings(findings: &[Value]) -> Vec<Value> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut unique = Vec::new();
    for finding in findings {
        let fp = format!(
            "{}\u{1}{}\u{1}{}\u{1}{}",
            finding.get("file").unwrap_or(&Value::Null),
            finding.get("startLine").unwrap_or(&Value::Null),
            finding.get("endLine").unwrap_or(&Value::Null),
            finding.get("rule_id").unwrap_or(&Value::Null),
        );
        if seen.insert(fp) {
            unique.push(finding.clone());
        }
    }
    unique
}

/// Tool name from a SARIF run (`get_tool_name`); `"unknown"` when absent/empty.
pub fn get_tool_name(run: &Value) -> String {
    run.get("tool")
        .and_then(|t| t.get("driver"))
        .and_then(|d| d.get("name"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

/// Rules from a SARIF run keyed by rule ID (`get_rules`); rules without a
/// truthy `id` are skipped.
pub fn get_rules(run: &Value) -> Map<String, Value> {
    let mut out = Map::new();
    let rules = run
        .get("tool")
        .and_then(|t| t.get("driver"))
        .and_then(|d| d.get("rules"))
        .and_then(Value::as_array);
    if let Some(rules) = rules {
        for r in rules {
            if let Some(id) = r.get("id").and_then(Value::as_str) {
                if !id.is_empty() {
                    out.insert(id.to_string(), r.clone());
                }
            }
        }
    }
    out
}

/// Sanitise a finding for display (`sanitize_finding_for_display`): truncate a
/// string `snippet` >500 chars and a string `message` >200 chars.
pub fn sanitize_finding_for_display(finding: &Value) -> Value {
    let mut sanitized = finding.clone();
    if let Some(obj) = sanitized.as_object_mut() {
        if let Some(s) = obj.get("snippet").and_then(Value::as_str) {
            if s.chars().count() > 500 {
                let truncated: String = s.chars().take(497).collect();
                obj.insert("snippet".to_string(), Value::String(format!("{truncated}...")));
            }
        }
        if let Some(s) = obj.get("message").and_then(Value::as_str) {
            if s.chars().count() > 200 {
                let truncated: String = s.chars().take(197).collect();
                obj.insert("message".to_string(), Value::String(format!("{truncated}...")));
            }
        }
    }
    sanitized
}

fn py_repr_str(s: &str) -> String {
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn py_repr_value(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => py_repr_str(s),
        // Nested containers are not expected in partialFingerprints; fall back
        // to a JSON rendering.
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cwe_extraction_shapes() {
        let cases = [
            (json!({"properties": {"cwe": "CWE-89"}}), Some("CWE-89")),
            (json!({"properties": {"cwe": ["CWE-89", "CWE-564"]}}), Some("CWE-89")),
            (json!({"properties": {"cwe_id": "cwe_190"}}), Some("CWE-190")),
            (json!({"properties": {"tags": ["external/cwe/cwe-79", "foo"]}}), Some("CWE-79")),
            (json!({"relationships": [{"target": {"id": "CWE-352"}}]}), Some("CWE-352")),
            (json!({"relationships": [{"target": {"id": "79", "toolComponent": {"name": "cwe"}}}]}), Some("CWE-79")),
            (json!({"relationships": [{"target": {"id": 22, "toolComponent": {"name": "CWE"}}}]}), Some("CWE-22")),
            (json!({"properties": {}}), None),
            (json!({}), None),
        ];
        for (rule, want) in cases {
            assert_eq!(extract_cwe_from_rule(&rule).as_deref(), want, "{rule}");
        }
    }

    #[test]
    fn result_key_cases() {
        let r = json!({"ruleId": "r1", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 10, "endLine": 12, "startColumn": 5}}}]});
        let k = result_key(&r);
        assert_eq!((k.rule_id.as_str(), k.uri.as_str(), k.line, k.end_line, k.start_col, k.fingerprint.as_str()),
            ("r1", "a.py", 10, 12, 5, ""));
        // endLine defaults to startLine when absent; primaryLocationLineHash used.
        let r = json!({"ruleId": "r2", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.py"}, "region": {"startLine": 3}}}], "partialFingerprints": {"primaryLocationLineHash": "abc"}});
        let k = result_key(&r);
        assert_eq!((k.line, k.end_line, k.start_col, k.fingerprint.as_str()), (3, 3, 0, "abc"));
        // Fallback: repr(sorted(fp.items())).
        let r = json!({"ruleId": "r3", "partialFingerprints": {"z": "1", "a": "2"}});
        assert_eq!(result_key(&r).fingerprint, "[('a', '2'), ('z', '1')]");
        // Empty result.
        let k = result_key(&json!({}));
        assert_eq!((k.rule_id.as_str(), k.uri.as_str(), k.line, k.fingerprint.as_str()), ("", "", 0, ""));
    }

    #[test]
    fn dedup_and_accessors() {
        let findings = vec![
            json!({"file": "a.py", "startLine": 1, "endLine": 1, "rule_id": "x"}),
            json!({"file": "a.py", "startLine": 1, "endLine": 1, "rule_id": "x"}),
            json!({"file": "a.py", "startLine": 2, "endLine": 2, "rule_id": "x"}),
        ];
        assert_eq!(deduplicate_findings(&findings).len(), 2);

        assert_eq!(get_tool_name(&json!({"tool": {"driver": {"name": "Semgrep"}}})), "Semgrep");
        assert_eq!(get_tool_name(&json!({})), "unknown");

        let rules = get_rules(&json!({"tool": {"driver": {"rules": [{"id": "r1", "x": 1}, {"id": "r2"}, {"noid": 1}]}}}));
        assert_eq!(rules.len(), 2);
        assert_eq!(rules["r1"], json!({"id": "r1", "x": 1}));
        assert!(rules.contains_key("r2"));
    }

    #[test]
    fn sanitize_truncation() {
        let long_s = "a".repeat(600);
        let long_m = "b".repeat(250);
        let out = sanitize_finding_for_display(&json!({"snippet": long_s, "message": long_m, "other": 1, "null_snip": null}));
        assert_eq!(out["snippet"].as_str().unwrap().chars().count(), 500);
        assert!(out["snippet"].as_str().unwrap().ends_with("..."));
        assert_eq!(out["message"].as_str().unwrap().chars().count(), 200);
        assert_eq!(out["other"], json!(1));
        // Null snippet/message are left untouched (no TypeError).
        let out = sanitize_finding_for_display(&json!({"snippet": null, "message": null}));
        assert_eq!(out, json!({"snippet": null, "message": null}));
    }
}
