//! Conan parser — Rust port of `packages/sca/parsers/conan.py` (the pure
//! `parse_txt` + `parse_lock`). `parse_py` (conanfile.py via CPython `ast`) is
//! the documented cross-language gap and is not ported.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "ConanCenter";
const PURL_TYPE: &str = "conan";

const TXT_SECTION_TO_SCOPE: &[(&str, &str)] = &[
    ("requires", "main"),
    ("tool_requires", "build"),
    ("test_requires", "test"),
    ("build_requires", "build"),
];
// conan.lock top-level array keys -> scope (Conan 2 shape).
const LOCK_KEY_TO_SCOPE: &[(&str, &str)] = &[
    ("requires", "main"),
    ("tool_requires", "build"),
    ("build_requires", "build"),
    ("test_requires", "test"),
    ("python_requires", "build"),
];

fn ref_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?P<name>[A-Za-z0-9._\-+]+)/(?P<version>\[[^\]]+\]|[A-Za-z0-9._\-+]+)(?:@(?P<userchannel>[A-Za-z0-9._\-+]+/[A-Za-z0-9._\-+]+))?(?:#[A-Fa-f0-9]+)?$",
        )
        .unwrap()
    })
}
fn bare_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9._\-+]+$").unwrap())
}

fn is_range(version: &str) -> bool {
    version.starts_with('[') && version.ends_with(']')
}

fn build_purl(name: &str, version: Option<&str>) -> String {
    let base = format!("pkg:{PURL_TYPE}/{name}");
    match version {
        Some(v) => format!("{base}@{v}"),
        None => base,
    }
}

fn split_ref(reference: &str) -> (Option<String>, Option<String>) {
    let r = reference.trim();
    if r.is_empty() {
        return (None, None);
    }
    if let Some(m) = ref_re().captures(r) {
        return (Some(m["name"].to_string()), Some(m["version"].to_string()));
    }
    if !r.contains('/') && bare_name_re().is_match(r) {
        return (Some(r.to_string()), None);
    }
    (None, None)
}

fn build_dep_from_ref(reference: &str, scope: &str, declared_in: &str, is_lockfile: bool) -> Option<Dependency> {
    let (name, version) = split_ref(reference);
    let name = name?;
    let pin_style = match version.as_deref() {
        Some(v) if !is_range(v) => PinStyle::Exact,
        Some(v) if is_range(v) => PinStyle::Range,
        _ => PinStyle::Wildcard,
    };
    let level = if version.is_some() { "high" } else { "medium" };
    let reason = if is_lockfile {
        "conan.lock pinned ref"
    } else if version.is_some() {
        "conanfile structured ref"
    } else {
        "conanfile ref without version"
    };
    Some(Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        purl: build_purl(&name, version.as_deref()),
        name,
        version,
        declared_in: declared_in.to_string(),
        scope: scope.to_string(),
        is_lockfile,
        pin_style,
        direct: !is_lockfile,
        parser_confidence: Confidence::new(level, reason),
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
        source_extra: None,
    })
}

/// Parse a `conanfile.txt` (`parse_txt`): refs grouped by `[requires]` sections.
pub fn parse_txt(content: &str, declared_in: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    let mut current_scope: Option<&str> = None;
    for line in content.split('\n') {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if stripped.starts_with('[') && stripped.ends_with(']') {
            let section = stripped[1..stripped.len() - 1].trim().to_lowercase();
            current_scope = TXT_SECTION_TO_SCOPE.iter().find(|(k, _)| *k == section).map(|(_, s)| *s);
            continue;
        }
        let Some(scope) = current_scope else { continue };
        if let Some(d) = build_dep_from_ref(stripped, scope, declared_in, false) {
            out.push(d);
        }
    }
    out
}

/// Parse a `conan.lock` (`parse_lock`): refs from the top-level requires arrays.
pub fn parse_lock(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_json::from_str::<Value>(content) else { return Vec::new() };
    if !data.is_object() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (key, scope) in LOCK_KEY_TO_SCOPE {
        let Some(block) = data.get(key).and_then(Value::as_array) else { continue };
        for ref_val in block {
            if let Some(r) = ref_val.as_str() {
                if let Some(d) = build_dep_from_ref(r, scope, declared_in, true) {
                    out.push(d);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conanfile_txt() {
        let src = "[requires]\nzlib/1.3\nopenssl/[>=3.0 <4.0]\nbarename\n\n[tool_requires]\ncmake/3.27.0\n\n[generators]\nCMakeDeps\n";
        let deps = parse_txt(src, "conanfile.txt");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("zlib").version.as_deref(), Some("1.3"));
        assert_eq!(by("zlib").pin_style, PinStyle::Exact);
        assert_eq!(by("openssl").pin_style, PinStyle::Range); // [...] range
        assert_eq!(by("barename").pin_style, PinStyle::Wildcard);
        assert_eq!(by("cmake").scope, "build");
        // generators section ignored.
        assert!(deps.iter().all(|d| d.name != "CMakeDeps"));
    }

    #[test]
    fn conan_lock() {
        // Revisions after `#` must be hex (the ref regex requires [A-Fa-f0-9]+);
        // a non-hex revision makes the whole ref unmatchable and the dep dropped.
        let src = r#"{"version": "0.5", "requires": ["zlib/1.3#abcdef", "fmt/10.1.1@user/channel"], "build_requires": ["cmake/3.27.0"]}"#;
        let deps = parse_lock(src, "conan.lock");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("zlib").version.as_deref(), Some("1.3"));
        assert!(by("zlib").is_lockfile);
        assert!(!by("zlib").direct);
        assert_eq!(by("fmt").version.as_deref(), Some("10.1.1"));
        assert_eq!(by("cmake").scope, "build");
    }
}
