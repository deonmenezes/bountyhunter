//! Poetry `poetry.lock` parser — Rust port of
//! `packages/sca/parsers/poetry_lock.py`. Takes already-read content.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::models::{Confidence, Dependency, PinStyle};
use crate::toml_util::{is_truthy, parse_toml};

const ECOSYSTEM: &str = "PyPI";

fn name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[-_.]+").unwrap())
}
fn normalise_name(name: &str) -> String {
    name_re().replace_all(name, "-").to_lowercase()
}
fn build_purl(name: &str, version: Option<&str>) -> String {
    let base = format!("pkg:pypi/{}", normalise_name(name));
    match version {
        Some(v) => format!("{base}@{v}"),
        None => base,
    }
}

fn confidence(pin_style: PinStyle, version: Option<&str>, base_reason: &str) -> Confidence {
    match pin_style {
        PinStyle::Git | PinStyle::Path => Confidence::new("medium", base_reason),
        _ if version.is_none() => Confidence::new("low", "poetry.lock entry without version"),
        _ => Confidence::new("high", base_reason),
    }
}

fn infer_scope(pkg: &Value) -> &'static str {
    match pkg.get("category").and_then(Value::as_str) {
        Some("dev") => "dev",
        _ => "main",
    }
}

fn str_field(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_string)
}

fn build_dep(pkg: &Value, declared_in: &str) -> Option<Dependency> {
    let name = pkg.get("name").and_then(Value::as_str).filter(|s| !s.is_empty())?;
    let version_text = pkg.get("version");
    let source = pkg.get("source").filter(|v| v.is_object());

    let source_type = source.and_then(|s| s.get("type")).and_then(Value::as_str);
    let (pin_style, version, reason): (PinStyle, Option<String>, String) = match source_type {
        Some("git") => {
            // First truthy of resolved_reference/reference, kept if a string;
            // else fall back to version.
            let s = source.unwrap();
            let ref_val = ["resolved_reference", "reference"]
                .iter()
                .filter_map(|k| s.get(*k))
                .find(|v| is_truthy(v));
            let version = match ref_val.and_then(Value::as_str) {
                Some(r) => Some(r.to_string()),
                None => str_field(version_text),
            };
            (PinStyle::Git, version, "poetry.lock git source".to_string())
        }
        Some(t @ ("file" | "directory" | "url")) => {
            (PinStyle::Path, str_field(version_text), format!("poetry.lock {t} source"))
        }
        _ => {
            let version = str_field(version_text);
            let pin = if version.is_some() { PinStyle::Exact } else { PinStyle::Wildcard };
            (pin, version, "poetry.lock resolved entry".to_string())
        }
    };

    let scope = infer_scope(pkg);
    Some(Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name: normalise_name(name),
        purl: build_purl(name, version.as_deref()),
        parser_confidence: confidence(pin_style, version.as_deref(), &reason),
        version,
        declared_in: declared_in.to_string(),
        scope: scope.to_string(),
        is_lockfile: true,
        pin_style,
        direct: false,
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
        source_extra: None,
    })
}

/// Parse a `poetry.lock` (`parse`): one Dependency per `[[package]]` entry.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Some(data) = parse_toml(content) else { return Vec::new() };
    let Some(packages) = data.get("package").and_then(Value::as_array) else { return Vec::new() };
    let mut deps = Vec::new();
    for pkg in packages {
        if !pkg.is_object() {
            continue;
        }
        if let Some(d) = build_dep(pkg, declared_in) {
            deps.push(d);
        }
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poetry_entries() {
        let src = r#"
[[package]]
name = "Flask_Foo"
version = "2.1.0"
category = "main"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"

[[package]]
name = "gitdep"
version = "0.0.0"
[package.source]
type = "git"
resolved_reference = "abc123def"

[[package]]
name = "localdep"
version = "1.0.0"
[package.source]
type = "directory"
"#;
        let deps = parse(src, "poetry.lock");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("flask-foo").version.as_deref(), Some("2.1.0"));
        assert_eq!(by("flask-foo").pin_style, PinStyle::Exact);
        assert_eq!(by("pytest").scope, "dev");
        assert_eq!(by("gitdep").pin_style, PinStyle::Git);
        assert_eq!(by("gitdep").version.as_deref(), Some("abc123def"));
        assert_eq!(by("localdep").pin_style, PinStyle::Path);
        assert_eq!(by("localdep").parser_confidence.reason, "poetry.lock directory source");
    }
}
