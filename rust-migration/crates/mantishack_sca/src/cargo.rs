//! Rust Cargo parser — Rust port of `packages/sca/parsers/cargo.py`.
//!
//! Parses `Cargo.toml` (manifest) + `Cargo.lock` (lockfile, TOML). Takes
//! already-read content.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::models::{Confidence, Dependency, PinStyle};
use crate::toml_util::parse_toml;

const ECOSYSTEM: &str = "Cargo";
const PURL_TYPE: &str = "cargo";
const SCOPE_MAP: &[(&str, &str)] = &[
    ("dependencies", "main"),
    ("dev-dependencies", "dev"),
    ("build-dependencies", "build"),
];

fn op_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*(=|\^|~|>=?|<=?)\s*(\d[^\s,]*)\s*$").unwrap())
}
fn bare_re() -> &'static Regex {
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

fn classify_version_spec(spec: &str) -> (PinStyle, Option<String>) {
    let s = spec.trim();
    if s.is_empty() {
        return (PinStyle::Unknown, None);
    }
    if s == "*" {
        return (PinStyle::Wildcard, None);
    }
    if s.contains(',') {
        return (PinStyle::Range, None);
    }
    if let Some(c) = op_re().captures(s) {
        let ver = c[2].to_string();
        return match &c[1] {
            "=" => (PinStyle::Exact, Some(ver)),
            "^" => (PinStyle::Caret, Some(ver)),
            "~" => (PinStyle::Tilde, Some(ver)),
            _ => (PinStyle::Range, Some(ver)),
        };
    }
    if bare_re().is_match(s) {
        return (PinStyle::Caret, Some(s.to_string()));
    }
    (PinStyle::Unknown, None)
}

fn lockfile_pin_style(source: Option<&str>) -> PinStyle {
    match source {
        None | Some("") => PinStyle::Path,
        Some(s) if s.starts_with("git+") => PinStyle::Git,
        _ => PinStyle::Exact,
    }
}

fn is_true(obj: &Map<String, Value>, key: &str) -> bool {
    obj.get(key) == Some(&Value::Bool(true))
}

fn build_dep(name: &str, spec: &Value, scope: &str, declared_in: &str) -> Option<Dependency> {
    let mut version: Option<String> = None;
    let mut pin_style = PinStyle::Unknown;
    let mut git_url: Option<String> = None;
    let mut path_ref: Option<String> = None;
    let mut is_workspace_inherit = false;
    let mut is_optional = false;
    let mut declared_features: Option<Vec<Value>> = None;

    if let Some(s) = spec.as_str() {
        version = Some(s.to_string());
        let (p, normalised) = classify_version_spec(s);
        pin_style = p;
        if let Some(n) = normalised {
            version = Some(n);
        }
    } else if let Some(obj) = spec.as_object() {
        if is_true(obj, "workspace") {
            is_workspace_inherit = true;
            pin_style = PinStyle::Unknown;
        } else if obj.contains_key("git") {
            git_url = obj.get("git").and_then(Value::as_str).map(str::to_string);
            pin_style = PinStyle::Git;
        } else if obj.contains_key("path") {
            path_ref = obj.get("path").and_then(Value::as_str).map(str::to_string);
            pin_style = PinStyle::Path;
        } else if let Some(v) = obj.get("version").and_then(Value::as_str) {
            version = Some(v.to_string());
            let (p, normalised) = classify_version_spec(v);
            pin_style = p;
            if let Some(n) = normalised {
                version = Some(n);
            }
        }
        if is_true(obj, "optional") {
            is_optional = true;
        }
        if let Some(feats) = obj.get("features").and_then(Value::as_array) {
            declared_features = Some(feats.clone());
        }
    } else {
        return None;
    }

    let source_extra = if is_optional || declared_features.is_some() || git_url.is_some() || path_ref.is_some() {
        let mut m = Map::new();
        if is_optional {
            m.insert("cargo_optional".to_string(), Value::Bool(true));
        }
        if let Some(f) = &declared_features {
            m.insert("cargo_features".to_string(), Value::Array(f.clone()));
        }
        if let Some(g) = &git_url {
            m.insert("cargo_git".to_string(), Value::String(g.clone()));
        }
        if let Some(p) = &path_ref {
            m.insert("cargo_path".to_string(), Value::String(p.clone()));
        }
        Some(Value::Object(m))
    } else {
        None
    };

    let reason = if is_workspace_inherit {
        "Cargo.toml TOML — deterministic; workspace-inherit"
    } else {
        "Cargo.toml TOML — deterministic"
    };
    Some(Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name: name.to_string(),
        purl: build_purl(name, version.as_deref()),
        version,
        declared_in: declared_in.to_string(),
        scope: scope.to_string(),
        is_lockfile: false,
        pin_style,
        direct: true,
        parser_confidence: Confidence::new("high", reason),
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
        source_extra,
    })
}

/// Parse a `Cargo.toml` (`parse_manifest`).
pub fn parse_manifest(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Some(data) = parse_toml(content) else { return Vec::new() };
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let push = |dep: Option<Dependency>, out: &mut Vec<Dependency>, seen: &mut Vec<String>| {
        if let Some(dep) = dep {
            let k = dep.key();
            if !seen.contains(&k) {
                seen.push(k);
                out.push(dep);
            }
        }
    };

    for (scope_key, scope) in SCOPE_MAP {
        if let Some(block) = data.get(scope_key).and_then(Value::as_object) {
            for (name, spec) in block {
                push(build_dep(name, spec, scope, declared_in), &mut out, &mut seen);
            }
        }
    }
    if let Some(targets) = data.get("target").and_then(Value::as_object) {
        for (_cfg, target_block) in targets {
            let Some(tb) = target_block.as_object() else { continue };
            for (scope_key, scope) in SCOPE_MAP {
                if let Some(inner) = tb.get(*scope_key).and_then(Value::as_object) {
                    for (name, spec) in inner {
                        push(build_dep(name, spec, scope, declared_in), &mut out, &mut seen);
                    }
                }
            }
        }
    }
    out
}

/// Parse a `Cargo.lock` (`parse_lockfile`).
pub fn parse_lockfile(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Some(data) = parse_toml(content) else { return Vec::new() };
    let Some(packages) = data.get("package").and_then(Value::as_array) else { return Vec::new() };
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for entry in packages {
        let Some(obj) = entry.as_object() else { continue };
        let Some(name) = obj.get("name").and_then(Value::as_str) else { continue };
        let Some(version) = obj.get("version").and_then(Value::as_str) else { continue };
        let pin_style = lockfile_pin_style(obj.get("source").and_then(Value::as_str));
        let dep = Dependency {
            ecosystem: ECOSYSTEM.to_string(),
            name: name.to_string(),
            version: Some(version.to_string()),
            declared_in: declared_in.to_string(),
            scope: "main".to_string(),
            is_lockfile: true,
            pin_style,
            direct: false,
            purl: build_purl(name, Some(version)),
            parser_confidence: Confidence::new("high", "Cargo.lock TOML — deterministic structure"),
            declared_license: None,
            commented_out: false,
            source_kind: "lockfile".to_string(),
            source_extra: None,
        };
        let k = dep.key();
        if !seen.contains(&k) {
            seen.push(k);
            out.push(dep);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn manifest_specs() {
        let src = r#"
[dependencies]
serde = "1.0"
tokio = { version = "1.35", features = ["full"], optional = true }
mycrate = { git = "https://github.com/x/y" }
localcrate = { path = "../local" }
exact = "=2.1.0"
inherited = { workspace = true }

[dev-dependencies]
criterion = "0.5"
"#;
        let deps = parse_manifest(src, "Cargo.toml");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        // bare "1.0" -> implicit caret.
        assert_eq!(by("serde").pin_style, PinStyle::Caret);
        assert_eq!(by("tokio").pin_style, PinStyle::Caret);
        assert_eq!(by("tokio").source_extra, Some(json!({"cargo_optional": true, "cargo_features": ["full"]})));
        assert_eq!(by("mycrate").pin_style, PinStyle::Git);
        assert_eq!(by("localcrate").pin_style, PinStyle::Path);
        assert_eq!(by("exact").pin_style, PinStyle::Exact);
        assert_eq!(by("inherited").pin_style, PinStyle::Unknown);
        assert!(by("inherited").parser_confidence.reason.contains("workspace-inherit"));
        assert_eq!(by("criterion").scope, "dev");
    }

    #[test]
    fn lockfile_entries() {
        let src = r#"
[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "gitdep"
version = "0.1.0"
source = "git+https://github.com/x/y#abc"

[[package]]
name = "localdep"
version = "0.1.0"
"#;
        let deps = parse_lockfile(src, "Cargo.lock");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("serde").pin_style, PinStyle::Exact);
        assert_eq!(by("gitdep").pin_style, PinStyle::Git);
        assert_eq!(by("localdep").pin_style, PinStyle::Path); // no source
    }
}
