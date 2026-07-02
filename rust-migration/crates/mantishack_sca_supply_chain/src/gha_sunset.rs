//! GHA action sunset detector — Rust port of `packages/sca/supply_chain/gha_sunset.py`.
//!
//! Fully pure: matches deps against the embedded curated `data/gha_sunset.json`
//! list and emits a `SupplyChainFinding` per action pinned to a sunset version.

use std::collections::HashMap;
use std::sync::OnceLock;

use mantishack_sca::{Confidence, Dependency};
use serde_json::{json, Value};

use crate::SupplyChainFinding;

const SUNSET_JSON: &str = include_str!("../../../../packages/sca/data/gha_sunset.json");

/// Load + index the curated sunset list (`load_sunset_map`). Keys starting with
/// `_` (`_doc`/`_schema`) and malformed records (no `sunset_versions` list) are
/// dropped.
fn sunset_map() -> &'static HashMap<String, Vec<Value>> {
    static MAP: OnceLock<HashMap<String, Vec<Value>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut out: HashMap<String, Vec<Value>> = HashMap::new();
        let Ok(Value::Object(data)) = serde_json::from_str::<Value>(SUNSET_JSON) else { return out };
        for (action_name, records) in data {
            if action_name.starts_with('_') {
                continue;
            }
            let Some(records) = records.as_array() else { continue };
            let valid: Vec<Value> = records
                .iter()
                .filter(|r| r.is_object() && r.get("sunset_versions").map(Value::is_array).unwrap_or(false))
                .cloned()
                .collect();
            if !valid.is_empty() {
                out.insert(action_name, valid);
            }
        }
        out
    })
}

/// `actions/cache/restore` → `actions/cache`; `owner/repo` returns itself
/// (`_parent_action`).
fn parent_action(name: &str) -> String {
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() <= 2 {
        name.to_string()
    } else {
        parts[..2].join("/")
    }
}

/// Emit one `SupplyChainFinding` per action pinned to a sunset version
/// (`scan_dependencies`).
pub fn scan_dependencies(deps: &[Dependency]) -> Vec<SupplyChainFinding> {
    let map = sunset_map();
    if map.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for dep in deps {
        if dep.ecosystem != "GitHub Actions" {
            continue;
        }
        let Some(version) = dep.version.as_deref().filter(|v| !v.is_empty()) else { continue };
        let parent = parent_action(&dep.name);
        for candidate in [dep.name.as_str(), parent.as_str()] {
            let Some(records) = map.get(candidate).filter(|r| !r.is_empty()) else { continue };
            for record in records {
                let Some(versions_raw) = record.get("sunset_versions").and_then(Value::as_array) else {
                    continue;
                };
                let matched = versions_raw
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|v| v.to_lowercase() == version.to_lowercase());
                if !matched {
                    continue;
                }
                out.push(build_finding(dep, version, record));
                break;
            }
            break;
        }
    }
    out
}

fn coerce_severity(raw: Option<&Value>) -> String {
    if let Some(s) = raw.and_then(Value::as_str) {
        let low = s.to_lowercase();
        if matches!(low.as_str(), "info" | "low" | "medium" | "high" | "critical") {
            return low;
        }
    }
    "medium".to_string()
}

fn build_finding(dep: &Dependency, version: &str, record: &Value) -> SupplyChainFinding {
    let severity = coerce_severity(record.get("severity"));
    let sunset_date = record.get("sunset_date").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("unannounced");
    let reason = record.get("reason").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("version retired");
    let replacement = record.get("replacement").and_then(Value::as_str).filter(|s| !s.is_empty());

    let mut detail = format!(
        "GHA action `{}@{version}` is sunset (date: {sunset_date}). {reason}",
        dep.name
    );
    if let Some(rep) = replacement {
        detail.push_str(&format!(" Recommended replacement: `{rep}`."));
    }
    let finding_id =
        format!("sca:supplychain:gha_action_sunset:{}:{}", dep.name, version).replace(' ', "_");
    SupplyChainFinding {
        finding_id,
        kind: "gha_action_sunset".to_string(),
        dependency: dep.clone(),
        detail,
        evidence: json!({
            "action": dep.name,
            "version": version,
            "sunset_date": sunset_date,
            "replacement": record.get("replacement").cloned().unwrap_or(Value::Null),
        }),
        severity,
        confidence: Confidence::new(
            "high",
            &format!("matched curated sunset record for {} at version {version}", dep.name),
        ),
        related_findings: Vec::new(),
        suppressed: false,
        suppression_reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantishack_sca::PinStyle;

    fn dep(name: &str, ver: &str, eco: &str) -> Dependency {
        Dependency {
            ecosystem: eco.to_string(),
            name: name.to_string(),
            version: Some(ver.to_string()),
            declared_in: "x".into(),
            scope: "main".into(),
            is_lockfile: false,
            pin_style: PinStyle::Exact,
            direct: true,
            purl: "p".into(),
            parser_confidence: Confidence::new("high", ""),
            declared_license: None,
            commented_out: false,
            source_kind: "manifest".into(),
            source_extra: None,
        }
    }

    #[test]
    fn parent() {
        assert_eq!(parent_action("actions/cache/restore"), "actions/cache");
        assert_eq!(parent_action("owner/repo"), "owner/repo");
        assert_eq!(parent_action("a"), "a");
    }

    #[test]
    fn matches_and_misses() {
        let f = &scan_dependencies(&[dep("actions/upload-artifact", "v3", "GitHub Actions")])[0];
        assert_eq!(f.finding_id, "sca:supplychain:gha_action_sunset:actions/upload-artifact:v3");
        assert_eq!(f.severity, "high");
        assert_eq!(f.detail, "GHA action `actions/upload-artifact@v3` is sunset (date: 2024-11-30). v3 sunset 2024-11-30; v4 changed archive/concurrency semantics \u{2014} workflows on v3 fail outright Recommended replacement: `v4`.");
        assert_eq!(f.evidence["replacement"], json!("v4"));

        // Case-insensitive version match; original casing preserved in output.
        let f = &scan_dependencies(&[dep("actions/upload-artifact", "V3", "GitHub Actions")])[0];
        assert_eq!(f.finding_id, "sca:supplychain:gha_action_sunset:actions/upload-artifact:V3");
        assert_eq!(f.evidence["version"], json!("V3"));

        // Sub-action matched via parent; dep.name kept in the finding.
        let f = &scan_dependencies(&[dep("actions/cache/restore", "v1", "GitHub Actions")])[0];
        assert_eq!(f.finding_id, "sca:supplychain:gha_action_sunset:actions/cache/restore:v1");
        assert_eq!(f.severity, "medium");

        // Non-sunset version / clean action / non-action -> nothing.
        assert!(scan_dependencies(&[dep("actions/upload-artifact", "v4", "GitHub Actions")]).is_empty());
        assert!(scan_dependencies(&[dep("actions/checkout", "v99", "GitHub Actions")]).is_empty());
        assert!(scan_dependencies(&[dep("x", "1", "npm")]).is_empty());
    }
}
