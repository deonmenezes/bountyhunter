//! npm `package-lock.json` parser — Rust port of
//! `packages/sca/parsers/package_lock_json.py`. Handles v2/v3 (flat `packages`
//! map) and v1 (recursive `dependencies` tree). Takes already-read content.
//!
//! Like the Python parser, `source_kind` is left at the default `"manifest"`.

use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "npm";
const ROOT_KEY_SCOPE: &[(&str, &str)] = &[
    ("dependencies", "main"),
    ("devDependencies", "dev"),
    ("peerDependencies", "peer"),
    ("optionalDependencies", "optional"),
];

fn build_purl(name: &str, version: Option<&str>) -> String {
    let base = format!("pkg:npm/{name}");
    match version {
        Some(v) => format!("{base}@{v}"),
        None => base,
    }
}

fn confidence(pin_style: PinStyle, version: Option<&str>) -> Confidence {
    match pin_style {
        PinStyle::Git => Confidence::new("medium", "package-lock.json git source"),
        PinStyle::Path => Confidence::new("medium", "package-lock.json file/url source"),
        _ if version.is_none() => Confidence::new("low", "package-lock.json entry without version"),
        _ => Confidence::new("high", "package-lock.json resolved entry"),
    }
}

fn is_true(entry: &Map<String, Value>, key: &str) -> bool {
    entry.get(key) == Some(&Value::Bool(true))
}

fn str_version(entry: &Map<String, Value>) -> Option<String> {
    entry.get("version").and_then(Value::as_str).map(str::to_string)
}

fn make_dep(name: &str, version: Option<&str>, scope: &str, pin_style: PinStyle, declared_in: &str, direct: bool) -> Dependency {
    Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name: name.to_string(),
        version: version.map(str::to_string),
        declared_in: declared_in.to_string(),
        scope: scope.to_string(),
        is_lockfile: true,
        pin_style,
        direct,
        purl: build_purl(name, version),
        parser_confidence: confidence(pin_style, version),
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
        source_extra: None,
    }
}

/// Parse a `package-lock.json` / `shrinkwrap.json` (`parse`).
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_json::from_str::<Value>(content) else { return Vec::new() };
    let Some(obj) = data.as_object() else { return Vec::new() };
    if obj.get("packages").and_then(Value::as_object).is_some() {
        return parse_v2_or_v3(obj, declared_in);
    }
    if obj.get("dependencies").and_then(Value::as_object).is_some() {
        return parse_v1(obj, declared_in);
    }
    Vec::new()
}

fn direct_names_from_root(root_entry: &Map<String, Value>) -> HashSet<String> {
    let mut names = HashSet::new();
    for (key, _scope) in ROOT_KEY_SCOPE {
        if let Some(block) = root_entry.get(*key).and_then(Value::as_object) {
            names.extend(block.keys().cloned());
        }
    }
    names
}

fn name_from_packages_key<'a>(key: &'a str, entry: &'a Map<String, Value>) -> Option<&'a str> {
    if let Some(explicit) = entry.get("name").and_then(Value::as_str) {
        if !explicit.is_empty() {
            return Some(explicit);
        }
    }
    let marker = "node_modules/";
    let idx = key.rfind(marker)?;
    Some(&key[idx + marker.len()..])
}

fn scope_from_packages_entry(entry: &Map<String, Value>) -> &'static str {
    if is_true(entry, "dev") {
        "dev"
    } else if is_true(entry, "peer") {
        "peer"
    } else if is_true(entry, "optional") {
        "optional"
    } else if is_true(entry, "devOptional") {
        "dev"
    } else {
        "main"
    }
}

fn classify_packages_entry(entry: &Map<String, Value>, version: Option<&str>) -> (PinStyle, Option<String>) {
    if let Some(resolved) = entry.get("resolved").and_then(Value::as_str) {
        if resolved.starts_with("git+") || resolved.starts_with("git:") || resolved.starts_with("git@") {
            return (PinStyle::Git, version.map(str::to_string));
        }
        if resolved.starts_with("file:") {
            return (PinStyle::Path, version.map(str::to_string));
        }
        if resolved.starts_with("http://") || resolved.starts_with("https://") {
            let pin = if version.is_some() { PinStyle::Exact } else { PinStyle::Path };
            return (pin, version.map(str::to_string));
        }
    }
    if version.is_none() {
        return (PinStyle::Wildcard, None);
    }
    (PinStyle::Exact, version.map(str::to_string))
}

fn parse_v2_or_v3(data: &Map<String, Value>, declared_in: &str) -> Vec<Dependency> {
    let packages = data.get("packages").and_then(Value::as_object).unwrap();
    let empty = Map::new();
    let root = packages.get("").and_then(Value::as_object).unwrap_or(&empty);
    let direct_names = direct_names_from_root(root);

    let mut deps = Vec::new();
    for (key, entry) in packages {
        if key.is_empty() {
            continue;
        }
        let Some(entry) = entry.as_object() else { continue };
        if is_true(entry, "link") {
            continue;
        }
        let Some(name) = name_from_packages_key(key, entry) else { continue };
        let version = str_version(entry);
        let scope = scope_from_packages_entry(entry);
        let (pin_style, version_for_record) = classify_packages_entry(entry, version.as_deref());
        let is_direct = direct_names.contains(name);
        deps.push(make_dep(name, version_for_record.as_deref(), scope, pin_style, declared_in, is_direct));
    }
    deps
}

fn parse_v1(data: &Map<String, Value>, declared_in: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    let Some(root_deps) = data.get("dependencies").and_then(Value::as_object) else { return out };
    let direct_names: HashSet<String> = root_deps.keys().cloned().collect();
    walk_v1(root_deps, declared_in, 0, &direct_names, &mut out);
    out
}

fn walk_v1(deps_block: &Map<String, Value>, declared_in: &str, depth: i32, direct_names: &HashSet<String>, out: &mut Vec<Dependency>) {
    if depth > 64 {
        return;
    }
    for (name, entry) in deps_block {
        let Some(entry) = entry.as_object() else { continue };
        let version = str_version(entry);
        let scope = if is_true(entry, "dev") {
            "dev"
        } else if is_true(entry, "optional") {
            "optional"
        } else {
            "main"
        };
        let pin_style = if let Some(r) = entry.get("resolved").and_then(Value::as_str) {
            if r.starts_with("git+") || r.starts_with("git:") || r.starts_with("git@") {
                PinStyle::Git
            } else if r.starts_with("file:") {
                PinStyle::Path
            } else if version.is_some() {
                PinStyle::Exact
            } else {
                PinStyle::Wildcard
            }
        } else if version.is_some() {
            PinStyle::Exact
        } else {
            PinStyle::Wildcard
        };
        let direct = depth == 0 && direct_names.contains(name);
        out.push(make_dep(name, version.as_deref(), scope, pin_style, declared_in, direct));

        if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
            walk_v1(nested, declared_in, depth + 1, direct_names, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn v3_flat_packages() {
        let src = json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"express": "^4.0.0"}, "devDependencies": {"jest": "^29.0.0"}},
                "node_modules/express": {"version": "4.18.2", "resolved": "https://registry/express"},
                "node_modules/jest": {"version": "29.5.0", "dev": true},
                "node_modules/@scope/util": {"version": "1.0.0"},
                "node_modules/linkpkg": {"link": true}
            }
        }).to_string();
        let deps = parse(&src, "package-lock.json");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("express").version.as_deref(), Some("4.18.2"));
        assert_eq!(by("express").pin_style, PinStyle::Exact);
        assert!(by("express").direct); // in root dependencies
        assert_eq!(by("jest").scope, "dev");
        assert!(by("jest").direct);
        assert!(!by("@scope/util").direct); // transitive
        assert!(deps.iter().all(|d| d.name != "linkpkg")); // link skipped
    }

    #[test]
    fn v1_recursive_tree() {
        let src = json!({
            "lockfileVersion": 1,
            "dependencies": {
                "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
                "c": {"version": "3.0.0", "dev": true}
            }
        }).to_string();
        let deps = parse(&src, "package-lock.json");
        assert_eq!(deps.len(), 3);
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert!(by("a").direct); // depth 0
        assert!(!by("b").direct); // nested
        assert_eq!(by("c").scope, "dev");
    }
}
