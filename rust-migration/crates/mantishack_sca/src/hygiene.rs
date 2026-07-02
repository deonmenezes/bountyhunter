//! Dependency-hygiene checks — Rust port of the per-dep detectors in
//! `packages/sca/hygiene.py`. The lockfile-missing / drift / cross-manifest
//! checks (which need Manifest + version_compare + filesystem context) and the
//! `evaluate` orchestrator land as those land; the pure per-dep pin checks port
//! here.

use crate::models::{Confidence, Dependency, HygieneFinding, PinStyle};

fn finding(kind: &str, dep: &Dependency, detail: String, severity: &str, confidence: Confidence) -> HygieneFinding {
    HygieneFinding {
        finding_id: format!("sca:hygiene:{}:{}:{}:{}", kind, dep.ecosystem, dep.name, dep.declared_in),
        kind: kind.to_string(),
        dependency: dep.clone(),
        detail,
        severity: severity.to_string(),
        confidence,
        related_findings: Vec::new(),
        suppressed: false,
        suppression_reason: None,
    }
}

/// Flag manifest entries with no version constraint (`check_unpinned`). Maven
/// entries with no version are exempt (parent-POM dependencyManagement idiom).
pub fn check_unpinned(deps: &[Dependency]) -> Vec<HygieneFinding> {
    let mut out = Vec::new();
    for d in deps {
        if d.is_lockfile {
            continue;
        }
        if d.ecosystem == "Maven" && d.version.is_none() {
            continue;
        }
        if matches!(d.pin_style, PinStyle::Wildcard | PinStyle::Unknown) || d.version.is_none() {
            out.push(finding(
                "unpinned_dependency",
                d,
                format!("{} declared without a version pin (pin_style={})", d.name, d.pin_style.as_str()),
                "medium",
                Confidence::new("high", "parser observed wildcard / no version"),
            ));
        }
    }
    out
}

/// Flag manifest entries with caret / tilde / range pinning (`check_loose_pin`).
pub fn check_loose_pin(deps: &[Dependency]) -> Vec<HygieneFinding> {
    let mut out = Vec::new();
    for d in deps {
        if d.is_lockfile {
            continue;
        }
        if matches!(d.pin_style, PinStyle::Caret | PinStyle::Tilde | PinStyle::Range) {
            let version = d.version.as_deref().filter(|v| !v.is_empty()).unwrap_or("*");
            out.push(finding(
                "loose_pin",
                d,
                format!(
                    "{} uses loose pinning ({} {}); range may admit new vulns silently",
                    d.name,
                    d.pin_style.as_str(),
                    version
                ),
                "low",
                Confidence::new("high", "parser observed caret/tilde/range pinning"),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, ps: PinStyle, version: Option<&str>, eco: &str, is_lockfile: bool) -> Dependency {
        Dependency {
            ecosystem: eco.to_string(),
            name: name.to_string(),
            version: version.map(str::to_string),
            declared_in: "pkg/package.json".to_string(),
            scope: "main".to_string(),
            is_lockfile,
            pin_style: ps,
            direct: true,
            purl: "p".to_string(),
            parser_confidence: Confidence::new("high", ""),
            declared_license: None,
            commented_out: false,
            source_kind: "manifest".to_string(),
            source_extra: None,
        }
    }

    #[test]
    fn unpinned() {
        let deps = [
            dep("a", PinStyle::Wildcard, Some("1.0"), "npm", false),
            dep("b", PinStyle::Unknown, Some("1.0"), "npm", false),
            dep("c", PinStyle::Exact, None, "npm", false), // exact but no version -> flagged
            dep("d", PinStyle::Exact, Some("2.0"), "npm", false), // fine
            dep("e", PinStyle::Wildcard, Some("1.0"), "npm", true), // lockfile skip
            dep("m", PinStyle::Unknown, None, "Maven", false), // Maven no-version exempt
        ];
        let out = check_unpinned(&deps);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].finding_id, "sca:hygiene:unpinned_dependency:npm:a:pkg/package.json");
        assert_eq!(out[0].detail, "a declared without a version pin (pin_style=wildcard)");
        assert_eq!(out[2].detail, "c declared without a version pin (pin_style=exact)");
        assert_eq!((out[0].severity.as_str(), out[0].confidence.level.as_str(), out[0].confidence.reason.as_str()),
            ("medium", "high", "parser observed wildcard / no version"));
    }

    #[test]
    fn loose_pin() {
        let deps = [
            dep("x", PinStyle::Caret, Some("^1.0"), "npm", false),
            dep("y", PinStyle::Tilde, Some("~2.0"), "npm", false),
            dep("z", PinStyle::Range, None, "npm", false), // version -> "*"
            dep("w", PinStyle::Exact, Some("3.0"), "npm", false), // fine
            dep("v", PinStyle::Caret, Some("^9"), "npm", true), // lockfile skip
        ];
        let out = check_loose_pin(&deps);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].detail, "x uses loose pinning (caret ^1.0); range may admit new vulns silently");
        assert_eq!(out[2].detail, "z uses loose pinning (range *); range may admit new vulns silently");
        assert_eq!((out[0].severity.as_str(), out[0].kind.as_str()), ("low", "loose_pin"));
        assert_eq!(out[0].finding_id, "sca:hygiene:loose_pin:npm:x:pkg/package.json");
    }
}
