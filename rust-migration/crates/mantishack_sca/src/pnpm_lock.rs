//! pnpm `pnpm-lock.yaml` parser — Rust port of
//! `packages/sca/parsers/pnpm_lock.py`. Takes already-read content.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "npm";

fn key_v6() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^/(?:@[^/]+/)?[^/@]+@(.+)$").unwrap())
}
fn key_v5() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^/(?:@[^/]+/)?[^/]+/(.+)$").unwrap())
}

fn build_purl(name: &str, version: Option<&str>) -> String {
    let base = format!("pkg:npm/{name}");
    match version {
        Some(v) => format!("{base}@{v}"),
        None => base,
    }
}

fn confidence(pin_style: PinStyle, version: Option<&str>) -> Confidence {
    match pin_style {
        PinStyle::Git => Confidence::new("medium", "pnpm-lock.yaml git source"),
        PinStyle::Path => Confidence::new("medium", "pnpm-lock.yaml file source"),
        _ if version.is_none() => Confidence::new("low", "pnpm-lock.yaml entry without version"),
        _ => Confidence::new("high", "pnpm-lock.yaml resolved entry"),
    }
}

fn strip_version_suffix(version: &str) -> String {
    match version.find('(') {
        Some(p) if p > 0 => version[..p].to_string(),
        _ => version.to_string(),
    }
}

/// Recover `(name, version)` from a `packages` map key. The name is everything
/// before the version separator; we reconstruct it by stripping the version the
/// regex captured (mirrors the named-group `name` of the Python regexes, which
/// Rust can't reference by overlapping form).
fn split_packages_key(key: &str) -> (Option<String>, Option<String>) {
    if let Some(m) = key_v6().captures(key) {
        let version = strip_version_suffix(&m[1]);
        // name = key without the leading '/' and the trailing '@<version-raw>'.
        let raw_ver = &m[1];
        let name = key[1..key.len() - raw_ver.len() - 1].to_string();
        return (Some(name), Some(version));
    }
    if let Some(m) = key_v5().captures(key) {
        let version = strip_version_suffix(&m[1]);
        let raw_ver = &m[1];
        let name = key[1..key.len() - raw_ver.len() - 1].to_string();
        return (Some(name), Some(version));
    }
    (None, None)
}

fn extract_direct_keys(holder: &Map<String, Value>, out: &mut HashSet<String>) {
    for bucket in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
        if let Some(block) = holder.get(bucket).and_then(Value::as_object) {
            out.extend(block.keys().cloned());
        }
    }
}

fn collect_direct_names(data: &Map<String, Value>) -> HashSet<String> {
    let mut names = HashSet::new();
    if let Some(importers) = data.get("importers").and_then(Value::as_object) {
        for imp in importers.values() {
            if let Some(o) = imp.as_object() {
                extract_direct_keys(o, &mut names);
            }
        }
    }
    extract_direct_keys(data, &mut names);
    names
}

fn scope_from_entry(entry: &Map<String, Value>) -> &'static str {
    if entry.get("dev") == Some(&Value::Bool(true)) {
        "dev"
    } else if entry.get("peer") == Some(&Value::Bool(true)) {
        "peer"
    } else if entry.get("optional") == Some(&Value::Bool(true)) {
        "optional"
    } else {
        "main"
    }
}

fn classify_packages_entry(entry: &Map<String, Value>, version: Option<&str>) -> (PinStyle, Option<String>) {
    if let Some(res) = entry.get("resolution").and_then(Value::as_object) {
        if res.contains_key("repo") || res.contains_key("commit") {
            return (PinStyle::Git, version.map(str::to_string));
        }
        if let Some(t) = res.get("tarball").and_then(Value::as_str) {
            if t.starts_with("file:") {
                return (PinStyle::Path, version.map(str::to_string));
            }
        }
    }
    if version.is_none() {
        return (PinStyle::Wildcard, None);
    }
    (PinStyle::Exact, version.map(str::to_string))
}

/// Parse a `pnpm-lock.yaml` (`parse`): one Dependency per `packages` entry.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_yaml::from_str::<Value>(content) else { return Vec::new() };
    let Some(obj) = data.as_object() else { return Vec::new() };
    let direct_names = collect_direct_names(obj);
    let Some(packages) = obj.get("packages").and_then(Value::as_object) else { return Vec::new() };
    let empty = Map::new();
    let mut deps = Vec::new();
    for (key, entry) in packages {
        let (name, version) = split_packages_key(key);
        let Some(name) = name else { continue };
        let entry_obj = entry.as_object().unwrap_or(&empty);
        let scope = scope_from_entry(entry_obj);
        let (pin_style, version_for_record) = classify_packages_entry(entry_obj, version.as_deref());
        deps.push(Dependency {
            ecosystem: ECOSYSTEM.to_string(),
            purl: build_purl(&name, version_for_record.as_deref()),
            parser_confidence: confidence(pin_style, version_for_record.as_deref()),
            direct: direct_names.contains(&name),
            name,
            version: version_for_record,
            declared_in: declared_in.to_string(),
            scope: scope.to_string(),
            is_lockfile: true,
            pin_style,
            declared_license: None,
            commented_out: false,
            source_kind: "manifest".to_string(),
            source_extra: None,
        });
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pnpm_entries() {
        let src = "lockfileVersion: '6.0'\n\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.21\n        version: 4.17.21\n\npackages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n    dev: false\n\n  /@types/node@20.10.5:\n    resolution: {integrity: sha512-def}\n    dev: true\n\n  /jest@29.0.3(typescript@5.0.0):\n    resolution: {integrity: sha512-ghi}\n";
        let deps = parse(src, "pnpm-lock.yaml");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("lodash").version.as_deref(), Some("4.17.21"));
        assert_eq!(by("lodash").pin_style, PinStyle::Exact);
        assert!(by("lodash").direct); // in importers
        assert_eq!(by("@types/node").scope, "dev");
        assert!(!by("@types/node").direct);
        // peer-key suffix stripped from the version.
        assert_eq!(by("jest").version.as_deref(), Some("29.0.3"));
    }
}
