//! PHP Composer parser — Rust port of `packages/sca/parsers/composer.py`.
//!
//! Parses `composer.json` (manifest) + `composer.lock` (lockfile). Takes
//! already-read content; file reading stays at the call site.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "Packagist";
const PURL_TYPE: &str = "composer";

fn exact_spec_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^v?\d[\w.\-+]*$").unwrap())
}
fn release_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^v?\d+(\.\d+)*[\w.\-+]*$").unwrap())
}

fn is_platform_req(name: &str) -> bool {
    name == "php" || name == "hhvm" || name.starts_with("ext-") || name.starts_with("lib-")
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
    if s.is_empty() || s == "*" {
        return (PinStyle::Wildcard, None);
    }
    if s.starts_with("dev-") {
        return (PinStyle::Git, Some(s.to_string()));
    }
    if s.contains('|') || s.contains(',') || s.contains(' ') {
        return (PinStyle::Range, None);
    }
    if let Some(rest) = s.strip_prefix('^') {
        return (PinStyle::Caret, Some(rest.to_string()));
    }
    if let Some(rest) = s.strip_prefix('~') {
        return (PinStyle::Tilde, Some(rest.to_string()));
    }
    if s.starts_with(">=") || s.starts_with("<=") || s.starts_with('>') || s.starts_with('<') {
        let bare = s.trim_start_matches(['<', '>', '=']).trim();
        return (PinStyle::Range, if bare.is_empty() { None } else { Some(bare.to_string()) });
    }
    if exact_spec_re().is_match(s) {
        return (PinStyle::Exact, Some(s.to_string()));
    }
    (PinStyle::Unknown, None)
}

fn looks_like_release_tag(version: &str) -> bool {
    release_tag_re().is_match(version)
}

#[allow(clippy::too_many_arguments)]
fn make_dep(
    name: &str,
    version: Option<&str>,
    declared_in: &str,
    scope: &str,
    is_lockfile: bool,
    pin_style: PinStyle,
    reason: &str,
) -> Dependency {
    Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name: name.to_string(),
        version: version.map(str::to_string),
        declared_in: declared_in.to_string(),
        scope: scope.to_string(),
        is_lockfile,
        pin_style,
        direct: !is_lockfile,
        purl: build_purl(name, version),
        parser_confidence: Confidence::new("high", reason),
        declared_license: None,
        commented_out: false,
        source_kind: if is_lockfile { "lockfile" } else { "manifest" }.to_string(),
    }
}

/// Parse a `composer.json`, one Dependency per declared dep (`parse_manifest`).
pub fn parse_manifest(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_json::from_str::<Value>(content) else { return Vec::new() };
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for (json_key, scope) in [
        ("require", "main"),
        ("require-dev", "dev"),
        ("replace", "replaces"),
        ("provide", "provides"),
    ] {
        let Some(block) = data.get(json_key).and_then(Value::as_object) else { continue };
        for (name, spec) in block {
            let Some(spec) = spec.as_str() else { continue };
            if is_platform_req(name) {
                continue;
            }
            let (pin_style, version) = classify_version_spec(spec);
            let dep = make_dep(
                name,
                version.as_deref(),
                declared_in,
                scope,
                false,
                pin_style,
                "composer.json JSON — deterministic structure",
            );
            let k = dep.key();
            if !seen.contains(&k) {
                seen.push(k);
                out.push(dep);
            }
        }
    }
    out
}

/// Parse a `composer.lock`, one Dependency per resolved entry (`parse_lockfile`).
pub fn parse_lockfile(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_json::from_str::<Value>(content) else { return Vec::new() };
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for (json_key, scope) in [("packages", "main"), ("packages-dev", "dev")] {
        let Some(block) = data.get(json_key).and_then(Value::as_array) else { continue };
        for entry in block {
            let Some(obj) = entry.as_object() else { continue };
            let Some(name) = obj.get("name").and_then(Value::as_str) else { continue };
            let Some(version) = obj.get("version").and_then(Value::as_str) else { continue };
            let source_is_git = obj
                .get("source")
                .and_then(Value::as_object)
                .and_then(|s| s.get("type"))
                .and_then(Value::as_str)
                == Some("git");
            let pin_style = if source_is_git && !looks_like_release_tag(version) {
                PinStyle::Git
            } else {
                PinStyle::Exact
            };
            let dep = make_dep(
                name,
                Some(version),
                declared_in,
                scope,
                true,
                pin_style,
                "composer.lock JSON — deterministic structure",
            );
            let k = dep.key();
            if !seen.contains(&k) {
                seen.push(k);
                out.push(dep);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_specs_and_scopes() {
        let src = r#"{"require": {"foo/bar": "^1.2", "baz/qux": "~2.0", "php": ">=8.0", "ranged/dep": ">=1.0 <2.0", "branch/dep": "dev-master"}, "require-dev": {"dev/tool": "3.1.4"}}"#;
        let deps = parse_manifest(src, "composer.json");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("foo/bar").pin_style, PinStyle::Caret);
        assert_eq!(by("foo/bar").version.as_deref(), Some("1.2"));
        assert_eq!(by("baz/qux").pin_style, PinStyle::Tilde);
        assert_eq!(by("ranged/dep").pin_style, PinStyle::Range); // space -> range
        assert_eq!(by("branch/dep").pin_style, PinStyle::Git);
        assert_eq!(by("dev/tool").scope, "dev");
        // platform req php skipped.
        assert!(deps.iter().all(|d| d.name != "php"));
    }

    #[test]
    fn lockfile_git_source() {
        let src = r#"{"packages": [
            {"name": "vendor/pkg", "version": "1.2.3"},
            {"name": "git/pkg", "version": "dev-main", "source": {"type": "git"}}
        ]}"#;
        let deps = parse_lockfile(src, "composer.lock");
        assert_eq!(deps[0].pin_style, PinStyle::Exact);
        // git source + non-release version -> Git.
        assert_eq!(deps[1].pin_style, PinStyle::Git);
        assert!(deps[1].is_lockfile);
    }
}
