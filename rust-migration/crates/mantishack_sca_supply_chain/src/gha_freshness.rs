//! GHA action freshness detector — Rust port of the pure core of
//! `packages/sca/supply_chain/gha_freshness.py`.
//!
//! The GitHub "latest tag" lookup (`client.get_latest_tag`) is HTTP and stays
//! call-site in Python; [`evaluate_dep`] takes the already-resolved latest tag
//! and returns the `SupplyChainFinding` for an action pinned majors behind.

use std::sync::OnceLock;

use mantishack_sca::{Confidence, Dependency};
use regex::Regex;
use serde_json::json;

use crate::SupplyChainFinding;

// majors_behind (1-based) -> severity; index 0 unused, 4+ clamps at "high".
const SEVERITY_LADDER: &[&str] = &["info", "info", "low", "medium", "high"];

fn major_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z\-]*v?(?P<major>\d+)(?:[.\-].*)?$").unwrap())
}

/// Pull the major-version integer out of a tag-shape string (`_extract_major`).
/// `None` for SHAs, branch names, calver tags (major ≥ 1000), or unparseable.
pub fn extract_major(version: &str) -> Option<i32> {
    if version.is_empty() {
        return None;
    }
    let caps = major_re().captures(version.trim())?;
    let major: i32 = caps.name("major")?.as_str().parse().ok()?;
    if major >= 1000 {
        return None; // calendar-year, not a semver major
    }
    Some(major)
}

/// Decide whether `dep` is pinned multiple majors behind its `latest_tag` and,
/// if so, build the finding (the pure body of `scan_dependencies`'s loop; the
/// `get_latest_tag` HTTP call is resolved by the caller and passed in).
pub fn evaluate_dep(dep: &Dependency, latest_tag: Option<&str>) -> Option<SupplyChainFinding> {
    if dep.ecosystem != "GitHub Actions" {
        return None;
    }
    let version = dep.version.as_deref().filter(|v| !v.is_empty())?;
    let pinned_major = extract_major(version)?;
    let latest_tag = latest_tag?;
    let latest_major = extract_major(latest_tag)?;
    if latest_major <= pinned_major {
        return None;
    }
    let gap = latest_major - pinned_major;
    let idx = (gap as usize).min(SEVERITY_LADDER.len() - 1);
    let severity = SEVERITY_LADDER[idx];
    Some(build_finding(dep, version, pinned_major, latest_tag, latest_major, gap, severity))
}

fn build_finding(
    dep: &Dependency,
    version: &str,
    pinned_major: i32,
    latest_tag: &str,
    latest_major: i32,
    gap: i32,
    severity: &str,
) -> SupplyChainFinding {
    let plural = if gap != 1 { "s" } else { "" };
    let detail = format!(
        "GHA action `{name}@{version}` is {gap} major version{plural} behind the latest release `{latest_tag}` (major {latest_major}). Upgrade for security fixes and to avoid the next sunset window.",
        name = dep.name,
    );
    let finding_id =
        format!("sca:supplychain:gha_action_outdated:{}:{}", dep.name, version).replace(' ', "_");
    SupplyChainFinding {
        finding_id,
        kind: "gha_action_outdated".to_string(),
        dependency: dep.clone(),
        detail,
        evidence: json!({
            "action": dep.name,
            "pinned_version": version,
            "pinned_major": pinned_major,
            "latest_tag": latest_tag,
            "latest_major": latest_major,
            "majors_behind": gap,
        }),
        severity: severity.to_string(),
        confidence: Confidence::new(
            "high",
            &format!("compared pinned major {pinned_major} against latest release {latest_tag}"),
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
    use serde_json::json;

    #[test]
    fn extract_major_cases() {
        assert_eq!(extract_major("v4"), Some(4));
        assert_eq!(extract_major("v1.2.3"), Some(1));
        assert_eq!(extract_major("release-2.0"), Some(2));
        assert_eq!(extract_major("2024.05.01"), None); // calver -> major >= 1000
        assert_eq!(extract_major("abc123def"), None);
        assert_eq!(extract_major(""), None);
        assert_eq!(extract_major("v0"), Some(0));
        assert_eq!(extract_major("3"), Some(3));
        assert_eq!(extract_major("1000"), None);
        assert_eq!(extract_major("999"), Some(999));
    }

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
    fn evaluate_cases() {
        let f = evaluate_dep(&dep("actions/checkout", "v3", "GitHub Actions"), Some("v4")).unwrap();
        assert_eq!(f.finding_id, "sca:supplychain:gha_action_outdated:actions/checkout:v3");
        assert_eq!(f.detail, "GHA action `actions/checkout@v3` is 1 major version behind the latest release `v4` (major 4). Upgrade for security fixes and to avoid the next sunset window.");
        assert_eq!(f.severity, "info");
        assert_eq!(f.confidence.reason, "compared pinned major 3 against latest release v4");
        assert_eq!(f.evidence, json!({"action": "actions/checkout", "pinned_version": "v3", "pinned_major": 3, "latest_tag": "v4", "latest_major": 4, "majors_behind": 1}));

        // 4-major gap clamps to high, plural "versions".
        let f = evaluate_dep(&dep("actions/setup-node", "v1", "GitHub Actions"), Some("v5")).unwrap();
        assert_eq!(f.severity, "high");
        assert!(f.detail.contains("is 4 major versions behind"));

        // 2-major gap -> low.
        assert_eq!(evaluate_dep(&dep("actions/cache", "v2", "GitHub Actions"), Some("v4")).unwrap().severity, "low");

        // Current / SHA / non-action / no-tag -> None.
        assert!(evaluate_dep(&dep("a/b", "v4", "GitHub Actions"), Some("v4")).is_none());
        assert!(evaluate_dep(&dep("a/b", "abc123", "GitHub Actions"), Some("v4")).is_none());
        assert!(evaluate_dep(&dep("lodash", "1.0", "npm"), None).is_none());
        assert!(evaluate_dep(&dep("a/b", "v1", "GitHub Actions"), None).is_none());
    }
}
