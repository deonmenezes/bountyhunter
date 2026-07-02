//! Transitive-drop pure helpers — Rust port of the self-contained functions in
//! `packages/sca/transitive_drop/detector.py`. The `_dep_state_*` registry
//! queries and `detect_droppable_transitives` orchestration are HTTP-bound and
//! stay Python; these name/severity/version helpers port here.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

const SEVERITY_ORDER: &[&str] = &["info", "low", "medium", "high", "critical"];

/// Per-ecosystem canonical-name normalisation (`_canonical_name`). Maven keeps
/// `groupId:artifactId` case (trim only); others case-fold + `_`→`-`.
pub fn canonical_name(ecosystem: &str, name: &str) -> String {
    if ecosystem == "Maven" {
        name.trim().to_string()
    } else {
        name.to_lowercase().replace('_', "-")
    }
}

fn severity_index(s: &str) -> Option<usize> {
    SEVERITY_ORDER.iter().position(|&x| x == s)
}

/// Higher of two severities (`_max_severity`). `a=None` → `b`; if either isn't a
/// known severity (Python `ValueError`) → `b`; ties keep `a` (Python `max`).
pub fn max_severity(a: Option<&str>, b: &str) -> String {
    let Some(a) = a else { return b.to_string() };
    match (severity_index(a), severity_index(b)) {
        (Some(ia), Some(ib)) => {
            if ia >= ib {
                a.to_string()
            } else {
                b.to_string()
            }
        }
        _ => b.to_string(),
    }
}

fn stable_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$").unwrap())
}

/// Numeric sort key for a version (`_version_key`); non-matching → `[0]`.
pub fn version_key(v: &str) -> Vec<i64> {
    match stable_re().captures(v) {
        Some(c) => (1..=4)
            .map(|i| c.get(i).map(|m| m.as_str().parse().unwrap_or(0)).unwrap_or(0))
            .collect(),
        None => vec![0],
    }
}

/// `_version_lt`: version_key(a) < version_key(b) lexicographically.
pub fn version_lt(a: &str, b: &str) -> bool {
    version_key(a) < version_key(b)
}

/// Candidate version strings from a registry metadata blob per ecosystem shape
/// (the pure part of `_latest_stable_version` after the HTTP fetch).
fn version_candidates(ecosystem: &str, meta: &Value) -> Vec<String> {
    let Some(meta) = meta.as_object() else { return Vec::new() };
    match ecosystem {
        "npm" => meta
            .get("versions")
            .and_then(Value::as_object)
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default(),
        "Packagist" => {
            let mut out = Vec::new();
            if let Some(pkgs) = meta.get("packages").and_then(Value::as_object) {
                for vlist in pkgs.values() {
                    if let Some(arr) = vlist.as_array() {
                        for v in arr {
                            if let Some(ver) = v.get("version").and_then(Value::as_str) {
                                if !ver.is_empty() {
                                    out.push(ver.to_string());
                                }
                            }
                        }
                    }
                }
            }
            out
        }
        _ => meta
            .get("releases")
            .and_then(Value::as_object)
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default(),
    }
}

/// Highest stable version from an already-fetched registry metadata blob
/// (`_latest_stable_version` minus the `client.get_metadata` call).
pub fn latest_stable_version(ecosystem: &str, meta: &Value) -> Option<String> {
    let mut stable: Vec<String> = version_candidates(ecosystem, meta)
        .into_iter()
        .filter(|v| stable_re().is_match(v))
        .collect();
    if stable.is_empty() {
        return None;
    }
    // Stable sort descending by version_key (matches Python sort(reverse=True)).
    stable.sort_by(|a, b| version_key(b).cmp(&version_key(a)));
    stable.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_names() {
        assert_eq!(canonical_name("Maven", " Org:Art "), "Org:Art");
        assert_eq!(canonical_name("PyPI", "Flask_Foo"), "flask-foo");
        assert_eq!(canonical_name("npm", "Lodash"), "lodash");
    }

    #[test]
    fn max_severities() {
        assert_eq!(max_severity(None, "low"), "low");
        assert_eq!(max_severity(Some("low"), "high"), "high");
        assert_eq!(max_severity(Some("high"), "low"), "high");
        assert_eq!(max_severity(Some("medium"), "medium"), "medium");
        assert_eq!(max_severity(Some("bogus"), "high"), "high"); // a invalid -> b
        assert_eq!(max_severity(Some("high"), "bogus"), "bogus"); // b invalid -> b
    }

    #[test]
    fn version_keys_and_lt() {
        assert_eq!(version_key("1.2.3"), vec![1, 2, 3, 0]);
        assert_eq!(version_key("v2.0"), vec![2, 0, 0, 0]);
        assert_eq!(version_key("1"), vec![1, 0, 0, 0]);
        assert_eq!(version_key("1.0.0.5"), vec![1, 0, 0, 5]);
        assert_eq!(version_key("garbage"), vec![0]);
        assert!(version_lt("2.9", "2.10"));
        assert!(version_lt("1.0.0", "1.0.1"));
        assert!(!version_lt("2.0", "1.9"));
        assert!(version_lt("bad", "1.0"));
    }

    #[test]
    fn latest_stable() {
        assert_eq!(latest_stable_version("PyPI", &json!({"releases": {"1.0": [], "2.1": [], "1.5": [], "2.0b1": []}})).as_deref(), Some("2.1"));
        assert_eq!(latest_stable_version("npm", &json!({"versions": {"1.0.0": {}, "1.2.0": {}, "1.10.0": {}}})).as_deref(), Some("1.10.0"));
        assert_eq!(latest_stable_version("Packagist", &json!({"packages": {"a/b": [{"version": "1.0"}, {"version": "3.0"}, {"version": "2.0"}]}})).as_deref(), Some("3.0"));
        assert_eq!(latest_stable_version("PyPI", &json!({"releases": {"main": [], "dev": []}})), None);
    }
}
