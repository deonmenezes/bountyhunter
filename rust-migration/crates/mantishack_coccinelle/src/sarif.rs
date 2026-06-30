//! Convert `SpatchResult` to SARIF 2.1.0 — faithful port of
//! `packages/coccinelle/sarif.py::results_to_sarif`.
//!
//! Pure conversion (no I/O) except `rel_to_repo`, which mirrors Python's
//! `Path(file).resolve().relative_to(repo.resolve())` to normalize an absolute
//! match path to repo-relative; anything that isn't an absolute path under the
//! repo is left exactly as-is.

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::models::SpatchResult;

const DEFAULT_LEVEL: &str = "warning";
const TOOL_NAME: &str = "coccinelle";
const TOOL_FULL_NAME: &str = "Coccinelle (spatch)";
const TOOL_INFO_URI: &str = "https://coccinelle.gitlabpages.inria.fr/website/";
const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master\
/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json";

/// Best-effort repo-relative path. Mirrors `_rel_to_repo`: empty stays empty, a
/// relative path passes through untouched, and an absolute path is made
/// repo-relative only when it resolves to a location under `repo_path` — a
/// cross-FS / non-repo absolute path (Python's `ValueError`/`OSError`) is left
/// as-is.
pub fn rel_to_repo(file_path: &str, repo_path: &Path) -> String {
    if file_path.is_empty() {
        return String::new();
    }
    let p = Path::new(file_path);
    if p.is_absolute() {
        // Python resolves symlinks on both sides before `relative_to`; canonicalize
        // does the same. If either side can't be resolved (non-existent path, the
        // cross-FS case), fall through and leave the path as-is.
        if let (Ok(rp), Ok(rr)) = (p.canonicalize(), repo_path.canonicalize()) {
            if let Ok(rel) = rp.strip_prefix(&rr) {
                return rel.to_string_lossy().into_owned();
            }
        }
        return file_path.to_string();
    }
    file_path.to_string()
}

/// Turn a sequence of per-rule `SpatchResult` into a SARIF 2.1.0 document.
pub fn results_to_sarif(results: &[SpatchResult], repo_path: &Path) -> Value {
    let mut rule_defs: Vec<Value> = Vec::new();
    let mut seen_rule_ids: Vec<String> = Vec::new();
    let mut sarif_results: Vec<Value> = Vec::new();
    let mut notifications: Vec<Value> = Vec::new();

    for r in results {
        let rule_id = if r.rule.is_empty() { "(unnamed)".to_string() } else { r.rule.clone() };
        if !seen_rule_ids.iter().any(|s| s == &rule_id) {
            let full_desc = if r.rule_path.is_empty() {
                format!("Coccinelle rule {rule_id}")
            } else {
                format!("Coccinelle rule emitted from {}", r.rule_path)
            };
            rule_defs.push(json!({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
                "fullDescription": {"text": full_desc},
                "defaultConfiguration": {"level": DEFAULT_LEVEL},
                "helpUri": TOOL_INFO_URI,
            }));
            seen_rule_ids.push(rule_id.clone());
        }

        for m in &r.matches {
            let file_rel = rel_to_repo(&m.file, repo_path);
            let message = if m.message.is_empty() {
                format!("{rule_id} matched")
            } else {
                m.message.clone()
            };
            // Region keys are emitted conditionally, matching the Python `**(... if ...)`
            // spreads: startLine always; endLine/startColumn/endColumn only when non-zero.
            let mut region = Map::new();
            region.insert("startLine".into(), json!(m.line));
            if m.line_end != 0 {
                region.insert("endLine".into(), json!(m.line_end));
            }
            if m.column != 0 {
                region.insert("startColumn".into(), json!(m.column));
            }
            if m.column_end != 0 {
                region.insert("endColumn".into(), json!(m.column_end));
            }
            sarif_results.push(json!({
                "ruleId": rule_id,
                "level": DEFAULT_LEVEL,
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_rel},
                        "region": Value::Object(region),
                    },
                }],
            }));
        }

        for err in &r.errors {
            let truncated: String = err.chars().take(500).collect();
            notifications.push(json!({
                "level": "error",
                "message": {"text": truncated},
                "associatedRule": {"id": rule_id},
            }));
        }
    }

    let mut run = Map::new();
    run.insert(
        "tool".into(),
        json!({
            "driver": {
                "name": TOOL_NAME,
                "fullName": TOOL_FULL_NAME,
                "informationUri": TOOL_INFO_URI,
                "rules": rule_defs,
            },
        }),
    );
    run.insert("results".into(), Value::Array(sarif_results));
    if !notifications.is_empty() {
        run.insert(
            "invocations".into(),
            json!([{
                "executionSuccessful": false,
                "toolExecutionNotifications": notifications,
            }]),
        );
    }

    json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [Value::Object(run)],
    })
}
