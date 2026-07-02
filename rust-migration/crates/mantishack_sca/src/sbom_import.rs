//! CycloneDX SBOM import — Rust port of the pure core of
//! `packages/sca/sbom_import.py`. The file read + top-level `parse_cyclonedx`
//! walk stay Python; purl parsing, license extraction, and component→Dependency
//! mapping port here.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::models::{Confidence, Dependency, PinStyle};

/// `pkg:<eco>/...` purl prefix → SCA's canonical (OSV) ecosystem label.
fn purl_eco(type_lc: &str) -> Option<&'static str> {
    Some(match type_lc {
        "pypi" => "PyPI",
        "npm" => "npm",
        "maven" => "Maven",
        "cargo" => "Cargo",
        "gem" | "rubygems" => "RubyGems",
        "golang" | "go" => "Go",
        "nuget" => "NuGet",
        "composer" => "Packagist",
        "github" => "GitHub",
        "deb" => "Debian",
        "rpm" => "RPM",
        "apk" => "Alpine",
        "oci" => "Container",
        _ => return None,
    })
}

/// CycloneDX `scope` enum → SCA scope (default `main`).
fn scope_map(raw: &str) -> &'static str {
    match raw {
        "required" => "main",
        "optional" => "optional",
        "excluded" => "excluded",
        _ => "main",
    }
}

fn purl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^pkg:(?P<type>[A-Za-z0-9.+-]+)/(?P<path>[^@?#]+)(?:@(?P<version>[^?#]+))?(?:[?#].*)?$")
            .unwrap()
    })
}

/// Parse `(ecosystem, name, version)` from a purl (`_parse_purl`); `None` for
/// malformed or unsupported ecosystems.
pub fn parse_purl(purl: &str) -> Option<(String, String, Option<String>)> {
    let caps = purl_re().captures(purl)?;
    let type_lc = caps.name("type").unwrap().as_str().to_lowercase();
    let ecosystem = purl_eco(&type_lc)?;
    let path = caps.name("path").unwrap().as_str();
    let version = caps.name("version").map(|m| m.as_str().to_string());

    let name = if ecosystem == "Maven" && path.contains('/') {
        let (group, artifact) = path.rsplit_once('/').unwrap();
        format!("{group}:{artifact}")
    } else if ecosystem == "Go" && path.contains('/') {
        path.to_string()
    } else if ecosystem == "npm" && path.starts_with("%40") {
        format!("@{}", &path[3..])
    } else {
        path.rsplit_once('/').map(|(_, n)| n).unwrap_or(path).to_string()
    };
    Some((ecosystem.to_string(), name, version))
}

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

fn py_str_trim(v: &Value) -> String {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    };
    s.trim().to_string()
}

/// First license expression / SPDX id from a CycloneDX `licenses` array
/// (`_extract_license`).
pub fn extract_license(licenses_block: &Value) -> Option<String> {
    let arr = licenses_block.as_array()?;
    for entry in arr {
        let Some(obj) = entry.as_object() else { continue };
        if let Some(expr) = obj.get("expression") {
            if json_truthy(expr) {
                return Some(py_str_trim(expr));
            }
        }
        if let Some(lic) = obj.get("license").filter(|v| v.is_object()) {
            for key in ["id", "name"] {
                if let Some(val) = lic.get(key) {
                    if json_truthy(val) {
                        return Some(py_str_trim(val));
                    }
                }
            }
        }
    }
    None
}

/// Convert one CycloneDX component → SCA `Dependency` (`_component_to_dep`);
/// `None` without a usable purl.
pub fn component_to_dep(comp: &Value, sbom_path: &str) -> Option<Dependency> {
    let purl = comp.get("purl").and_then(Value::as_str).filter(|s| !s.is_empty())?;
    let (ecosystem, name, version) = parse_purl(purl)?;

    let scope_raw = comp.get("scope").and_then(Value::as_str).unwrap_or("required");
    let scope = scope_map(scope_raw);
    let declared_license = comp.get("licenses").and_then(|b| extract_license(b));
    let pin_style = if version.is_some() { PinStyle::Exact } else { PinStyle::Unknown };

    Some(Dependency {
        ecosystem,
        name,
        version,
        declared_in: sbom_path.to_string(),
        scope: scope.to_string(),
        is_lockfile: true, // SBOM = resolved snapshot
        pin_style,
        direct: true,
        purl: purl.to_string(),
        parser_confidence: Confidence::new("high", "imported from CycloneDX SBOM"),
        declared_license,
        commented_out: false,
        source_kind: "sbom_import".to_string(),
        source_extra: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pp(p: &str) -> Option<(String, String, Option<String>)> {
        parse_purl(p)
    }

    #[test]
    fn purls() {
        assert_eq!(pp("pkg:pypi/flask@2.0.0"), Some(("PyPI".into(), "flask".into(), Some("2.0.0".into()))));
        assert_eq!(pp("pkg:npm/%40types/node@20.0.0"), Some(("npm".into(), "@types/node".into(), Some("20.0.0".into()))));
        assert_eq!(pp("pkg:maven/org.apache/commons@1.0"), Some(("Maven".into(), "org.apache:commons".into(), Some("1.0".into()))));
        assert_eq!(pp("pkg:golang/github.com/gin-gonic/gin@1.9"), Some(("Go".into(), "github.com/gin-gonic/gin".into(), Some("1.9".into()))));
        assert_eq!(pp("pkg:cargo/serde@1.0"), Some(("Cargo".into(), "serde".into(), Some("1.0".into()))));
        assert_eq!(pp("pkg:pypi/requests"), Some(("PyPI".into(), "requests".into(), None)));
        assert_eq!(pp("pkg:npm/lodash@4.17.21?arch=x64#sub"), Some(("npm".into(), "lodash".into(), Some("4.17.21".into()))));
        assert_eq!(pp("pkg:bogus/x@1"), None);
        assert_eq!(pp("not-a-purl"), None);
    }

    #[test]
    fn licenses() {
        assert_eq!(extract_license(&json!([{"license": {"id": "Apache-2.0"}}])).as_deref(), Some("Apache-2.0"));
        assert_eq!(extract_license(&json!([{"license": {"name": "Custom"}}])).as_deref(), Some("Custom"));
        assert_eq!(extract_license(&json!([{"expression": "Apache-2.0 OR MIT"}])).as_deref(), Some("Apache-2.0 OR MIT"));
        assert_eq!(extract_license(&json!([{"foo": 1}])), None);
        assert_eq!(extract_license(&json!("x")), None);
    }

    #[test]
    fn components() {
        let d = component_to_dep(&json!({"purl": "pkg:npm/lodash@4.17.21", "scope": "optional", "licenses": [{"license": {"id": "MIT"}}]}), "sbom.json").unwrap();
        assert_eq!((d.ecosystem.as_str(), d.name.as_str(), d.version.as_deref()), ("npm", "lodash", Some("4.17.21")));
        assert_eq!((d.scope.as_str(), d.is_lockfile, d.pin_style), ("optional", true, PinStyle::Exact));
        assert_eq!((d.declared_license.as_deref(), d.source_kind.as_str()), (Some("MIT"), "sbom_import"));
        assert_eq!(d.parser_confidence.reason, "imported from CycloneDX SBOM");

        assert!(component_to_dep(&json!({"name": "x", "version": "1"}), "sbom.json").is_none()); // no purl
        // Default scope -> main, no license.
        let d = component_to_dep(&json!({"purl": "pkg:pypi/flask@2.0"}), "sbom.json").unwrap();
        assert_eq!((d.scope.as_str(), d.declared_license.as_deref()), ("main", None));
    }
}
