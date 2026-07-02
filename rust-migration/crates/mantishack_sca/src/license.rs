//! License SPDX extraction — Rust port of the self-contained SPDX helpers in
//! `packages/sca/license.py`. The policy engine (`evaluate`/`_classify`) needs
//! the LicensePolicy + LicenseFinding models, and the registry `_fetch_*`
//! functions are HTTP; both stay Python. The pure SPDX-string extractors port
//! here.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::models::{Confidence, Dependency, LicenseFinding};

const SPDX_SUPPORTED_ECOSYSTEMS: &[&str] =
    &["PyPI", "npm", "Maven", "Cargo", "RubyGems", "NuGet", "Packagist"];

/// Operator-defined license rules (`LicensePolicy`).
#[derive(Clone, Debug, PartialEq)]
pub struct LicensePolicy {
    pub allow: HashSet<String>,
    pub deny: HashSet<String>,
    pub warn: HashSet<String>,
    pub default: String,
    pub on_unknown: String,
}

fn set_of(items: &[&str]) -> HashSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// The no-config baseline policy (`DEFAULT_POLICY`).
pub fn default_policy() -> LicensePolicy {
    LicensePolicy {
        allow: HashSet::new(),
        deny: set_of(&["AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "Commons-Clause", "BUSL-1.1"]),
        warn: set_of(&[
            "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
            "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
        ]),
        default: "allow".to_string(),
        on_unknown: "warn".to_string(),
    }
}

/// CPython `repr()` for a str over the printable/common-escape range.
fn py_repr(s: &str) -> String {
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

fn finding_id(dep: &Dependency, kind: &str) -> String {
    let version = dep.version.as_deref().filter(|v| !v.is_empty()).unwrap_or("*");
    format!("sca:{kind}:{}:{}@{}:{}", dep.ecosystem, dep.name, version, dep.declared_in)
}

fn deny_finding(dep: &Dependency, spdx: &str, why: &str) -> LicenseFinding {
    LicenseFinding {
        finding_id: finding_id(dep, "license_denied"),
        kind: "license_denied".to_string(),
        dependency: dep.clone(),
        spdx: Some(spdx.to_string()),
        detail: format!("License {} {why}", py_repr(spdx)),
        severity: "high".to_string(),
        confidence: Confidence::new("high", why),
        suppressed: false,
        suppression_reason: None,
    }
}

fn warn_finding(dep: &Dependency, spdx: &str, why: &str) -> LicenseFinding {
    LicenseFinding {
        finding_id: finding_id(dep, "license_warned"),
        kind: "license_warned".to_string(),
        dependency: dep.clone(),
        spdx: Some(spdx.to_string()),
        detail: format!("License {} {why}", py_repr(spdx)),
        severity: "medium".to_string(),
        confidence: Confidence::new("high", why),
        suppressed: false,
        suppression_reason: None,
    }
}

fn unknown_finding(dep: &Dependency, policy: &LicensePolicy) -> Option<LicenseFinding> {
    if policy.on_unknown == "allow" {
        return None;
    }
    let severity = if policy.on_unknown == "deny" { "high" } else { "info" };
    let version = dep.version.as_deref().filter(|v| !v.is_empty()).unwrap_or("*");
    Some(LicenseFinding {
        finding_id: finding_id(dep, "license_unknown"),
        kind: "license_unknown".to_string(),
        dependency: dep.clone(),
        spdx: None,
        detail: format!(
            "No license metadata for {}:{}@{} \u{2014} registry returned no SPDX field",
            dep.ecosystem, dep.name, version
        ),
        severity: severity.to_string(),
        confidence: Confidence::new("medium", "declared_license is None after enrichment"),
        suppressed: false,
        suppression_reason: None,
    })
}

fn classify(dep: &Dependency, spdx: &str, policy: &LicensePolicy) -> Option<LicenseFinding> {
    if policy.deny.contains(spdx) {
        return Some(deny_finding(dep, spdx, "in policy.deny"));
    }
    if policy.warn.contains(spdx) {
        return Some(warn_finding(dep, spdx, "in policy.warn"));
    }
    if policy.allow.contains(spdx) {
        return None;
    }
    match policy.default.as_str() {
        "deny" => Some(deny_finding(dep, spdx, "not in policy.allow")),
        "warn" => Some(warn_finding(dep, spdx, "not in policy.allow")),
        _ => None,
    }
}

fn evaluate_or(dep: &Dependency, spdx: &str, policy: &LicensePolicy) -> Option<LicenseFinding> {
    let classified: Vec<Option<LicenseFinding>> =
        spdx.split(" OR ").map(|c| classify(dep, c.trim(), policy)).collect();
    if classified.iter().any(Option::is_none) {
        return None; // one choice satisfies the policy
    }
    if classified.iter().all(|f| f.as_ref().unwrap().kind == "license_denied") {
        return Some(deny_finding(dep, spdx, "in policy.deny"));
    }
    Some(LicenseFinding {
        finding_id: finding_id(dep, "license_incompatible"),
        kind: "license_incompatible".to_string(),
        dependency: dep.clone(),
        spdx: Some(spdx.to_string()),
        detail: format!(
            "Multi-license OR expression {} has no choice that satisfies the policy; operator must pick one or update policy.allow",
            py_repr(spdx)
        ),
        severity: "medium".to_string(),
        confidence: Confidence::new("medium", "OR expression with no policy-satisfying choice"),
        suppressed: false,
        suppression_reason: None,
    })
}

fn evaluate_and(dep: &Dependency, spdx: &str, policy: &LicensePolicy) -> Option<LicenseFinding> {
    for c in spdx.split(" AND ") {
        if let Some(f) = classify(dep, c.trim(), policy) {
            return Some(f);
        }
    }
    None
}

fn evaluate_one(dep: &Dependency, policy: &LicensePolicy) -> Option<LicenseFinding> {
    let spdx = dep.declared_license.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let Some(spdx) = spdx else {
        return unknown_finding(dep, policy);
    };
    if spdx.contains(" OR ") {
        return evaluate_or(dep, spdx, policy);
    }
    if spdx.contains(" AND ") {
        return evaluate_and(dep, spdx, policy);
    }
    if spdx.contains(" WITH ") {
        let base = spdx.split(" WITH ").next().unwrap_or(spdx).trim();
        return classify(dep, base, policy);
    }
    classify(dep, spdx, policy)
}

/// Classify each dep's `declared_license` against the policy (`evaluate`).
/// Dedups by `Dependency.key()`; non-SPDX ecosystems are skipped.
pub fn evaluate(deps: &[Dependency], policy: &LicensePolicy) -> Vec<LicenseFinding> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for d in deps {
        if !SPDX_SUPPORTED_ECOSYSTEMS.contains(&d.ecosystem.as_str()) {
            continue;
        }
        let key = d.key();
        if !seen.insert(key) {
            continue;
        }
        if let Some(f) = evaluate_one(d, policy) {
            out.push(f);
        }
    }
    out
}

fn spdx_expr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[A-Za-z0-9.+\-]+(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9.+\-]+)+$").unwrap()
    })
}

/// True when `text` matches the SPDX compound-expression shape
/// (`_looks_like_spdx_expression`): `<id> (AND|OR|WITH) <id> …`.
pub fn looks_like_spdx_expression(text: &str) -> bool {
    spdx_expr_re().is_match(text.trim())
}

/// Map a PyPI `License ::` Trove classifier to an SPDX id (`_spdx_from_trove`);
/// `None` for unknown classifiers.
pub fn spdx_from_trove(classifier: &str) -> Option<&'static str> {
    let m: &[(&str, &str)] = &[
        ("License :: OSI Approved :: MIT License", "MIT"),
        ("License :: OSI Approved :: Apache Software License", "Apache-2.0"),
        ("License :: OSI Approved :: BSD License", "BSD-3-Clause"),
        ("License :: OSI Approved :: ISC License (ISCL)", "ISC"),
        ("License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)", "MPL-2.0"),
        ("License :: OSI Approved :: GNU General Public License v2 (GPLv2)", "GPL-2.0"),
        ("License :: OSI Approved :: GNU General Public License v3 (GPLv3)", "GPL-3.0"),
        ("License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)", "GPL-3.0-or-later"),
        ("License :: OSI Approved :: GNU Affero General Public License v3", "AGPL-3.0"),
        ("License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)", "AGPL-3.0-or-later"),
        ("License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)", "LGPL-2.0"),
        ("License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)", "LGPL-2.0-or-later"),
        ("License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)", "LGPL-3.0"),
        ("License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)", "LGPL-3.0-or-later"),
        ("License :: Public Domain", "Unlicense"),
        ("License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication", "CC0-1.0"),
    ];
    let key = classifier.trim();
    m.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

/// Extract an SPDX string from an npm `license`/`licenses` block
/// (`_spdx_from_npm_block`): a string, an object with `type`, or a list of
/// either.
pub fn spdx_from_npm_block(block: &Value) -> Option<String> {
    match block {
        Value::String(s) => {
            let t = s.trim();
            (!t.is_empty()).then(|| t.to_string())
        }
        Value::Object(o) => o.get("type").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string),
        Value::Array(a) => {
            for item in a {
                match item {
                    Value::Object(o) => {
                        if let Some(t) = o.get("type").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) {
                            return Some(t.to_string());
                        }
                    }
                    Value::String(s) => {
                        let t = s.trim();
                        if !t.is_empty() {
                            return Some(t.to_string());
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        _ => None,
    }
}

/// Extract the SPDX license from npm registry metadata (`_spdx_from_npm`).
/// Per-version `license`/`licenses` wins over the top-level.
pub fn spdx_from_npm(meta: &Value, version: Option<&str>) -> Option<String> {
    let meta = meta.as_object()?;
    if let Some(version) = version.filter(|v| !v.is_empty()) {
        if let Some(versions) = meta.get("versions").and_then(Value::as_object) {
            if let Some(v_meta) = versions.get(version).filter(|v| v.is_object()) {
                if let Some(s) = spdx_from_npm_block(v_meta.get("license").unwrap_or(&Value::Null)) {
                    return Some(s);
                }
                if let Some(s) = spdx_from_npm_block(v_meta.get("licenses").unwrap_or(&Value::Null)) {
                    return Some(s);
                }
            }
        }
    }
    if let Some(s) = spdx_from_npm_block(meta.get("license").unwrap_or(&Value::Null)) {
        return Some(s);
    }
    spdx_from_npm_block(meta.get("licenses").unwrap_or(&Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn spdx_expression_shape() {
        assert!(!looks_like_spdx_expression("MIT")); // no operator
        assert!(looks_like_spdx_expression("MIT OR Apache-2.0"));
        assert!(looks_like_spdx_expression("GPL-2.0 WITH Classpath-exception-2.0"));
        assert!(looks_like_spdx_expression("A AND B AND C"));
        assert!(!looks_like_spdx_expression("see LICENSE file"));
        assert!(!looks_like_spdx_expression("MIT ")); // trimmed, still no operator
    }

    #[test]
    fn trove_mapping() {
        assert_eq!(spdx_from_trove("License :: OSI Approved :: MIT License"), Some("MIT"));
        assert_eq!(spdx_from_trove("License :: Public Domain"), Some("Unlicense"));
        assert_eq!(spdx_from_trove("Unknown"), None);
    }

    #[test]
    fn npm_blocks_and_meta() {
        assert_eq!(spdx_from_npm_block(&json!("  MIT  ")).as_deref(), Some("MIT"));
        assert_eq!(spdx_from_npm_block(&json!({"type": "ISC", "url": "x"})).as_deref(), Some("ISC"));
        assert_eq!(spdx_from_npm_block(&json!([{"foo": 1}, {"type": "BSD-3-Clause"}])).as_deref(), Some("BSD-3-Clause"));
        assert_eq!(spdx_from_npm_block(&json!(["Apache-2.0"])).as_deref(), Some("Apache-2.0"));
        assert_eq!(spdx_from_npm_block(&json!({"url": "x"})), None);

        // Per-version override wins over top-level.
        assert_eq!(spdx_from_npm(&json!({"license": "MIT", "versions": {"1.0": {"license": "GPL-3.0"}}}), Some("1.0")).as_deref(), Some("GPL-3.0"));
        // Falls back to top-level when the version block has no license.
        assert_eq!(spdx_from_npm(&json!({"license": "MIT", "versions": {"1.0": {}}}), Some("1.0")).as_deref(), Some("MIT"));
        // Legacy top-level `licenses` list.
        assert_eq!(spdx_from_npm(&json!({"licenses": [{"type": "BSD-2-Clause"}]}), None).as_deref(), Some("BSD-2-Clause"));
    }

    use crate::models::{Confidence, PinStyle};

    fn dep(lic: Option<&str>, eco: &str) -> Dependency {
        Dependency {
            ecosystem: eco.into(), name: "pkg".into(), version: Some("1.0".into()),
            declared_in: "pkg/package.json".into(), scope: "main".into(), is_lockfile: false,
            pin_style: PinStyle::Exact, direct: true, purl: "p".into(),
            parser_confidence: Confidence::new("high", ""),
            declared_license: lic.map(str::to_string),
            commented_out: false, source_kind: "manifest".into(), source_extra: None,
        }
    }
    fn ev(lic: Option<&str>, eco: &str) -> Vec<LicenseFinding> {
        evaluate(&[dep(lic, eco)], &default_policy())
    }

    #[test]
    fn policy_classification() {
        assert!(ev(Some("MIT"), "npm").is_empty()); // allowed by default
        let f = &ev(Some("AGPL-3.0"), "npm")[0];
        assert_eq!((f.kind.as_str(), f.severity.as_str(), f.detail.as_str()),
            ("license_denied", "high", "License 'AGPL-3.0' in policy.deny"));
        assert_eq!(f.finding_id, "sca:license_denied:npm:pkg@1.0:pkg/package.json");
        let f = &ev(Some("GPL-3.0"), "npm")[0];
        assert_eq!((f.kind.as_str(), f.severity.as_str()), ("license_warned", "medium"));

        // OR: MIT satisfies -> no finding.
        assert!(ev(Some("MIT OR AGPL-3.0"), "npm").is_empty());
        // OR all-deny -> deny with the full expression.
        let f = &ev(Some("AGPL-3.0 OR SSPL-1.0"), "npm")[0];
        assert_eq!((f.kind.as_str(), f.detail.as_str()), ("license_denied", "License 'AGPL-3.0 OR SSPL-1.0' in policy.deny"));
        // AND: any warn propagates (the offending choice).
        assert_eq!(ev(Some("MIT AND GPL-3.0"), "npm")[0].spdx.as_deref(), Some("GPL-3.0"));
        // WITH: base license evaluated.
        assert_eq!(ev(Some("GPL-2.0 WITH Classpath-exception-2.0"), "npm")[0].spdx.as_deref(), Some("GPL-2.0"));
        // Unknown (on_unknown=warn -> info).
        let f = &ev(None, "npm")[0];
        assert_eq!((f.kind.as_str(), f.severity.as_str()), ("license_unknown", "info"));
        assert_eq!(f.detail, "No license metadata for npm:pkg@1.0 \u{2014} registry returned no SPDX field");
        // Unsupported ecosystem skipped.
        assert!(ev(Some("MIT"), "GitHub Actions").is_empty());
    }

    #[test]
    fn evaluate_dedups() {
        let deps = [dep(Some("AGPL-3.0"), "npm"), dep(Some("AGPL-3.0"), "npm")];
        assert_eq!(evaluate(&deps, &default_policy()).len(), 1);
    }
}
