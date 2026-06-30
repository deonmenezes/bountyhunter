//! vcpkg `vcpkg.json` parser — Rust port of `packages/sca/parsers/vcpkg.py`.
//! Takes already-read content.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "vcpkg";

fn port_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9][a-z0-9\-]*$").unwrap())
}

fn build_purl(name: &str, version: Option<&str>) -> String {
    let base = format!("pkg:vcpkg/{name}");
    match version {
        Some(v) => format!("{base}@{v}"),
        None => base,
    }
}

fn classify(entry: &Map<String, Value>) -> (Option<String>, PinStyle) {
    for field in ["version", "version-semver", "version-date", "version-string"] {
        if let Some(v) = entry.get(field).and_then(Value::as_str) {
            if !v.is_empty() {
                return (Some(v.to_string()), PinStyle::Exact);
            }
        }
    }
    if let Some(v) = entry.get("version>=").and_then(Value::as_str) {
        if !v.is_empty() {
            return (Some(v.to_string()), PinStyle::Range);
        }
    }
    (None, PinStyle::Wildcard)
}

fn confidence(pin_style: PinStyle, version: Option<&str>) -> Confidence {
    if pin_style == PinStyle::Exact && version.is_some() {
        Confidence::new("high", "vcpkg.json structured field")
    } else if pin_style == PinStyle::Range && version.is_some() {
        Confidence::new("medium", "vcpkg.json minimum-version constraint")
    } else {
        Confidence::new("medium", "vcpkg.json port name only")
    }
}

fn build_dep(entry: &Value, scope: &str, declared_in: &str) -> Option<Dependency> {
    let (name, version, pin_style) = if let Some(s) = entry.as_str() {
        (s.to_string(), None, PinStyle::Wildcard)
    } else if let Some(obj) = entry.as_object() {
        let name = obj.get("name").and_then(Value::as_str)?.to_string();
        let (v, p) = classify(obj);
        (name, v, p)
    } else {
        return None;
    };
    if !port_name_re().is_match(&name) {
        return None;
    }
    Some(Dependency {
        purl: build_purl(&name, version.as_deref()),
        parser_confidence: confidence(pin_style, version.as_deref()),
        ecosystem: ECOSYSTEM.to_string(),
        name,
        version,
        declared_in: declared_in.to_string(),
        scope: scope.to_string(),
        is_lockfile: false,
        pin_style,
        direct: true,
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
        source_extra: None,
    })
}

fn extract_block(block: Option<&Value>, scope: &str, declared_in: &str, out: &mut Vec<Dependency>) {
    if let Some(arr) = block.and_then(Value::as_array) {
        for entry in arr {
            if let Some(d) = build_dep(entry, scope, declared_in) {
                out.push(d);
            }
        }
    }
}

/// Parse a `vcpkg.json` (`parse`): deps from the top-level + per-feature blocks.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_json::from_str::<Value>(content) else { return Vec::new() };
    if !data.is_object() {
        return Vec::new();
    }
    let mut deps = Vec::new();
    extract_block(data.get("dependencies"), "main", declared_in, &mut deps);
    if let Some(features) = data.get("features").and_then(Value::as_object) {
        for (_, feat) in features {
            if let Some(fobj) = feat.as_object() {
                extract_block(fobj.get("dependencies"), "main", declared_in, &mut deps);
            }
        }
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcpkg_entries() {
        let src = r#"{
            "dependencies": [
                "fmt",
                {"name": "boost", "version>=": "1.80.0"},
                {"name": "zlib", "version": "1.3"},
                {"name": "Bad_Name"},
                {"noname": true}
            ],
            "features": {
                "ssl": {"dependencies": ["openssl"]}
            }
        }"#;
        let deps = parse(src, "vcpkg.json");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("fmt").pin_style, PinStyle::Wildcard);
        assert_eq!(by("boost").pin_style, PinStyle::Range);
        assert_eq!(by("boost").version.as_deref(), Some("1.80.0"));
        assert_eq!(by("zlib").pin_style, PinStyle::Exact);
        assert_eq!(by("openssl").scope, "main"); // from features
        // invalid port name + nameless skipped.
        assert!(deps.iter().all(|d| d.name != "Bad_Name"));
        assert_eq!(deps.len(), 4);
    }
}
