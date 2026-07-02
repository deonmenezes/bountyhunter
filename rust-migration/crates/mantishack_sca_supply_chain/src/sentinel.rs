//! Known-malicious package sentinel detector — Rust port of
//! `packages/sca/supply_chain/sentinel.py`.
//!
//! Matches deps against the curated `data/sentinel_packages.json` list (embedded
//! at build time). An exact (ecosystem, name) match on a covered version yields a
//! critical, high-confidence finding.

use std::collections::HashMap;
use std::sync::OnceLock;

use mantishack_sca::{Confidence, Dependency};
use serde_json::Value;

const SENTINEL_JSON: &str =
    include_str!("../../../../packages/sca/data/sentinel_packages.json");

/// A known-malicious package match (`SentinelHit`).
#[derive(Clone, Debug, PartialEq)]
pub struct SentinelHit {
    pub dependency: Dependency,
    pub incident: String,
    pub ref_: String,
    pub severity: String,
    pub confidence: Confidence,
}

struct SentinelEntry {
    versions: Vec<String>,
    incident: String,
    ref_: String,
}

/// Load + index `data/sentinel_packages.json` by (ecosystem, name.lower())
/// (mirrors `_load_sentinels`).
fn sentinels() -> &'static HashMap<(String, String), Vec<SentinelEntry>> {
    static CACHE: OnceLock<HashMap<(String, String), Vec<SentinelEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out: HashMap<(String, String), Vec<SentinelEntry>> = HashMap::new();
        let Ok(data) = serde_json::from_str::<Value>(SENTINEL_JSON) else { return out };
        let Some(packages) = data.get("packages").and_then(Value::as_array) else { return out };
        for entry in packages {
            let eco = entry.get("ecosystem").and_then(Value::as_str).unwrap_or("");
            let name = entry.get("name").and_then(Value::as_str).unwrap_or("").to_lowercase();
            if eco.is_empty() || name.is_empty() {
                continue;
            }
            // `entry.get("versions", ["*"])` — default to wildcard when absent.
            let versions = match entry.get("versions").and_then(Value::as_array) {
                Some(arr) => arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
                None => vec!["*".to_string()],
            };
            let incident = entry.get("incident").and_then(Value::as_str)
                .unwrap_or("known-malicious package").to_string();
            let ref_ = entry.get("ref").and_then(Value::as_str).unwrap_or("").to_string();
            out.entry((eco.to_string(), name)).or_default().push(SentinelEntry { versions, incident, ref_ });
        }
        out
    })
}

/// Match every dep against the sentinel list (`scan_deps`).
pub fn scan_deps(deps: &[Dependency]) -> Vec<SentinelHit> {
    let table = sentinels();
    if table.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for dep in deps {
        let key = (dep.ecosystem.clone(), dep.name.to_lowercase());
        let Some(entries) = table.get(&key) else { continue };
        for entry in entries {
            let version_match = entry.versions.iter().any(|v| v == "*")
                || dep
                    .version
                    .as_deref()
                    .filter(|v| !v.is_empty())
                    .map(|v| entry.versions.iter().any(|ev| ev == v))
                    .unwrap_or(false);
            if !version_match {
                continue;
            }
            let dedup_key = format!(
                "{}:{}:{}",
                dep.ecosystem,
                dep.name,
                dep.version.as_deref().unwrap_or("None")
            );
            if !seen.insert(dedup_key) {
                continue;
            }
            hits.push(SentinelHit {
                dependency: dep.clone(),
                incident: entry.incident.clone(),
                ref_: entry.ref_.clone(),
                severity: "critical".to_string(),
                confidence: Confidence::new(
                    "high",
                    &format!("exact match in sentinel list: {}", entry.incident),
                ),
            });
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantishack_sca::PinStyle;

    fn dep(name: &str, eco: &str, ver: &str) -> Dependency {
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
    fn versioned_match_and_miss() {
        let hits = scan_deps(&[dep("event-stream", "npm", "3.3.6")]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].incident, "flatmap-stream backdoor (2018)");
        assert_eq!(hits[0].ref_, "CVE-2018-16492");
        assert_eq!(hits[0].severity, "critical");
        assert_eq!(hits[0].confidence.level, "high");
        assert_eq!(hits[0].confidence.reason, "exact match in sentinel list: flatmap-stream backdoor (2018)");
        // Non-covered version does not match.
        assert!(scan_deps(&[dep("event-stream", "npm", "9.9.9")]).is_empty());
        // Clean package.
        assert!(scan_deps(&[dep("lodash", "npm", "1.0")]).is_empty());
    }

    #[test]
    fn case_insensitive_name_and_dedup() {
        assert_eq!(scan_deps(&[dep("Event-Stream", "npm", "3.3.6")]).len(), 1);
        // Same dep twice dedups to one hit.
        assert_eq!(scan_deps(&[dep("event-stream", "npm", "3.3.6"), dep("event-stream", "npm", "3.3.6")]).len(), 1);
    }
}
