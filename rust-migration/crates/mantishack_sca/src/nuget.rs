//! NuGet parser — Rust port of `packages/sca/parsers/nuget.py`
//! (`parse_packages_config` + `parse_lockfile`). The `.csproj`/`.fsproj`
//! PackageReference parser resolves versions through the Directory.Packages.props
//! CPM chain (filesystem walk-up) and is not ported here. Takes already-read
//! content.

use std::sync::OnceLock;

use regex::Regex;
use roxmltree::Document;
use serde_json::Value;

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "NuGet";
const PURL_TYPE: &str = "nuget";

fn bracket_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*([\[\(])\s*([^,\[\]\(\)]*?)\s*(?:,\s*([^,\[\]\(\)]*?)\s*)?([\]\)])\s*$").unwrap())
}
fn plain_ver_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d[\w.\-+]*$").unwrap())
}

fn build_purl(name: &str, version: Option<&str>) -> String {
    let base = format!("pkg:{PURL_TYPE}/{name}");
    match version {
        Some(v) => format!("{base}@{v}"),
        None => base,
    }
}

fn classify_version_spec(spec: Option<&str>) -> (PinStyle, Option<String>) {
    let Some(spec) = spec else { return (PinStyle::Unknown, None) };
    let s = spec.trim();
    if s.is_empty() {
        return (PinStyle::Unknown, None);
    }
    if let Some(m) = bracket_re().captures(s) {
        let lb = m.get(1).map_or("", |x| x.as_str());
        let lv = m.get(2).map_or("", |x| x.as_str());
        let ub = m.get(4).map_or("", |x| x.as_str());
        match m.get(3) {
            None => {
                if !lv.is_empty() && lb == "[" && ub == "]" {
                    return (PinStyle::Exact, Some(lv.to_string()));
                }
                (PinStyle::Unknown, None)
            }
            Some(uv) => {
                let uv = uv.as_str();
                let bare = if !lv.is_empty() {
                    Some(lv.to_string())
                } else if !uv.is_empty() {
                    Some(uv.to_string())
                } else {
                    None
                };
                (PinStyle::Range, bare)
            }
        }
    } else if plain_ver_re().is_match(s) {
        (PinStyle::Range, Some(s.to_string()))
    } else {
        (PinStyle::Unknown, None)
    }
}

fn dedup_push(dep: Dependency, out: &mut Vec<Dependency>, seen: &mut Vec<String>) {
    let k = dep.key();
    if !seen.contains(&k) {
        seen.push(k);
        out.push(dep);
    }
}

/// Parse a legacy `packages.config` (`parse_packages_config`).
pub fn parse_packages_config(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(doc) = Document::parse(content) else { return Vec::new() };
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for el in doc.root_element().descendants().filter(roxmltree::Node::is_element) {
        if el.tag_name().name() != "package" {
            continue;
        }
        let (Some(name), Some(version)) = (el.attribute("id"), el.attribute("version")) else { continue };
        if name.is_empty() || version.is_empty() {
            continue;
        }
        let (pin_style, normalised) = classify_version_spec(Some(version));
        let version_s = normalised.unwrap_or_else(|| version.to_string());
        let dep = Dependency {
            ecosystem: ECOSYSTEM.to_string(),
            name: name.to_string(),
            purl: build_purl(name, Some(&version_s)),
            version: Some(version_s),
            declared_in: declared_in.to_string(),
            scope: "main".to_string(),
            is_lockfile: false,
            pin_style,
            direct: true,
            parser_confidence: Confidence::new("high", "packages.config XML — deterministic structure"),
            declared_license: None,
            commented_out: false,
            source_kind: "manifest".to_string(),
            source_extra: None,
        };
        dedup_push(dep, &mut out, &mut seen);
    }
    out
}

/// Parse a `packages.lock.json` (`parse_lockfile`).
pub fn parse_lockfile(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_json::from_str::<Value>(content) else { return Vec::new() };
    let Some(deps_block) = data.get("dependencies").and_then(Value::as_object) else { return Vec::new() };
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for (_target, entries) in deps_block {
        let Some(entries) = entries.as_object() else { continue };
        for (name, spec) in entries {
            let Some(spec) = spec.as_object() else { continue };
            let Some(version) = spec.get("resolved").and_then(Value::as_str) else { continue };
            let kind = spec.get("type").and_then(Value::as_str).unwrap_or("").trim().to_lowercase();
            let direct = kind == "direct";
            let dep = Dependency {
                ecosystem: ECOSYSTEM.to_string(),
                name: name.clone(),
                version: Some(version.to_string()),
                declared_in: declared_in.to_string(),
                scope: "main".to_string(),
                is_lockfile: true,
                pin_style: PinStyle::Exact,
                direct,
                purl: build_purl(name, Some(version)),
                parser_confidence: Confidence::new("high", &format!("packages.lock.json — deterministic JSON; type='{kind}'")),
                declared_license: None,
                commented_out: false,
                source_kind: "lockfile".to_string(),
                source_extra: None,
            };
            dedup_push(dep, &mut out, &mut seen);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packages_config() {
        let src = r#"<?xml version="1.0"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
  <package id="NLog" version="[5.2.8]" />
  <package id="Ranged" version="[1.0,2.0)" />
  <package id="dup" version="1.0" />
  <package id="dup" version="1.0" />
  <package version="1.0" />
</packages>"#;
        let deps = parse_packages_config(src, "packages.config");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("Newtonsoft.Json").pin_style, PinStyle::Range); // bare -> minimum/range
        assert_eq!(by("NLog").pin_style, PinStyle::Exact); // [5.2.8]
        assert_eq!(by("NLog").version.as_deref(), Some("5.2.8"));
        assert_eq!(by("Ranged").pin_style, PinStyle::Range);
        assert_eq!(by("Ranged").version.as_deref(), Some("1.0")); // lower bound
        // dup@1.0 declared twice -> same key -> deduped to one.
        assert_eq!(by("dup").version.as_deref(), Some("1.0"));
        assert_eq!(deps.len(), 4);
    }

    #[test]
    fn packages_lock_json() {
        let src = r#"{"version": 1, "dependencies": {"net8.0": {
            "Foo": {"type": "Direct", "requested": "[1.2.3, )", "resolved": "1.2.3"},
            "Bar": {"type": "Transitive", "resolved": "2.0.0"}
        }}}"#;
        let deps = parse_lockfile(src, "packages.lock.json");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert!(by("Foo").direct);
        assert_eq!(by("Foo").version.as_deref(), Some("1.2.3"));
        assert!(!by("Bar").direct);
        assert!(by("Bar").is_lockfile);
    }
}
