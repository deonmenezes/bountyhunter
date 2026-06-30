//! Pipenv `Pipfile.lock` parser — Rust port of
//! `packages/sca/parsers/pipfile_lock.py`. Takes already-read content.
//!
//! Note: like the Python parser, this leaves `source_kind` at the default
//! `"manifest"` even though `is_lockfile` is true (the Python `_build_dep`
//! doesn't override it) — preserved faithfully.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "PyPI";
const SECTIONS: &[(&str, &str)] = &[("default", "main"), ("develop", "dev")];

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

/// `==X` -> `X`; bare value passes through; empty/non-string -> None (`_strip_eq`).
fn strip_eq(value: Option<&Value>) -> Option<String> {
    let v = value?.as_str()?.trim();
    if let Some(rest) = v.strip_prefix("==") {
        let r = rest.trim();
        if r.is_empty() { None } else { Some(r.to_string()) }
    } else if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn confidence(pin_style: PinStyle, version: Option<&str>) -> Confidence {
    match pin_style {
        PinStyle::Git => Confidence::new("medium", "Pipfile.lock git source; ref recorded as version"),
        PinStyle::Path => Confidence::new("medium", "Pipfile.lock path/file source; no version"),
        _ if version.is_none() => Confidence::new("low", "Pipfile.lock entry without version"),
        _ => Confidence::new("high", "Pipfile.lock resolved entry"),
    }
}

fn build_dep(name: &str, entry: &Value, scope: &str, declared_in: &str) -> Option<Dependency> {
    let obj = entry.as_object()?;
    let (pin_style, version) = if obj.contains_key("git") {
        // First truthy of ref/rev/tag/branch, kept only if it's a string.
        let raw = ["ref", "rev", "tag", "branch"]
            .iter()
            .filter_map(|k| obj.get(*k))
            .find(|v| is_truthy(v));
        (PinStyle::Git, raw.and_then(Value::as_str).map(str::to_string))
    } else if obj.contains_key("path") || obj.contains_key("file") {
        (PinStyle::Path, None)
    } else {
        let version = strip_eq(obj.get("version"));
        let pin = if version.is_some() { PinStyle::Exact } else { PinStyle::Wildcard };
        (pin, version)
    };
    Some(Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name: normalise_name(name),
        version: version.clone(),
        declared_in: declared_in.to_string(),
        scope: scope.to_string(),
        is_lockfile: true,
        pin_style,
        direct: false,
        purl: build_purl(name, version.as_deref()),
        parser_confidence: confidence(pin_style, version.as_deref()),
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
        source_extra: None,
    })
}

/// Parse a `Pipfile.lock` (`parse`): one Dependency per `default`/`develop` entry.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_json::from_str::<Value>(content) else { return Vec::new() };
    if !data.is_object() {
        return Vec::new();
    }
    let mut deps = Vec::new();
    for (section, scope) in SECTIONS {
        let Some(block) = data.get(section).and_then(Value::as_object) else { continue };
        for (name, entry) in block {
            if let Some(d) = build_dep(name, entry, scope, declared_in) {
                deps.push(d);
            }
        }
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lock_entries() {
        let src = json!({
            "default": {
                "Flask_Foo": {"version": "==2.1.0"},
                "gitdep": {"git": "https://x", "ref": "abc123"},
                "pathdep": {"path": "./local"},
                "noversion": {"markers": "python_version >= '3'"}
            },
            "develop": {"pytest": {"version": "==7.4.0"}}
        }).to_string();
        let deps = parse(&src, "Pipfile.lock");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        // name normalisation: Flask_Foo -> flask-foo.
        assert_eq!(by("flask-foo").version.as_deref(), Some("2.1.0"));
        assert_eq!(by("flask-foo").pin_style, PinStyle::Exact);
        assert_eq!(by("gitdep").pin_style, PinStyle::Git);
        assert_eq!(by("gitdep").version.as_deref(), Some("abc123"));
        assert_eq!(by("pathdep").pin_style, PinStyle::Path);
        assert_eq!(by("noversion").pin_style, PinStyle::Wildcard);
        assert_eq!(by("noversion").parser_confidence.level, "low");
        assert_eq!(by("pytest").scope, "dev");
        // source_kind stays "manifest" (faithful to the Python omission).
        assert_eq!(by("pytest").source_kind, "manifest");
    }
}
