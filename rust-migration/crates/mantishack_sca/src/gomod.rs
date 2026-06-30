//! Go module parser — Rust port of `packages/sca/parsers/gomod.py`.
//!
//! Parses `go.mod` (manifest) and `go.sum` (lockfile). The file read stays at
//! the call site; these take already-read `text` plus the `declared_in` path.

use std::sync::OnceLock;

use regex::Regex;

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "Go";
const PURL_TYPE: &str = "golang";

fn pseudo_version_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^v\d+\.\d+\.\d+(?:-[\w.]+)?-\d{14}-[0-9a-f]{12}$").unwrap())
}
fn require_single_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^require\s+(\S+)\s+(\S+)\s*(//.*)?$").unwrap())
}
fn require_block_open_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^require\s*\(\s*$").unwrap())
}
fn inner_entry_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(\S+)\s+(\S+)\s*(//.*)?$").unwrap())
}
fn replace_single_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^replace\s+(\S+)(?:\s+\S+)?\s*=>\s*(\S+)(?:\s+(\S+))?\s*$").unwrap())
}
fn replace_block_open_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^replace\s*\(\s*$").unwrap())
}
fn replace_inner_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(\S+)(?:\s+\S+)?\s*=>\s*(\S+)(?:\s+(\S+))?\s*$").unwrap())
}
fn exact_version_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^v\d+(\.\d+){0,2}$").unwrap())
}
fn exact_version_pre_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^v\d+(\.\d+){0,2}(?:-[\w.]+)?$").unwrap())
}

fn is_indirect(comment: &str) -> bool {
    comment.contains("indirect")
}

/// `(name, version, indirect)` for every `require` entry (`_parse_require_block`).
fn parse_require_block(text: &str) -> Vec<(String, String, bool)> {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let stripped = lines[i].trim_end().trim_start();
        if let Some(m) = require_single_re().captures(stripped) {
            let comment = m.get(3).map_or("", |c| c.as_str());
            out.push((m[1].to_string(), m[2].to_string(), is_indirect(comment)));
            i += 1;
            continue;
        }
        if require_block_open_re().is_match(stripped) {
            i += 1;
            while i < lines.len() {
                let inner = lines[i].trim_end().trim_start();
                if inner.starts_with(')') {
                    i += 1;
                    break;
                }
                if inner.is_empty() || inner.starts_with("//") {
                    i += 1;
                    continue;
                }
                if let Some(im) = inner_entry_re().captures(inner) {
                    let comment = im.get(3).map_or("", |c| c.as_str());
                    out.push((im[1].to_string(), im[2].to_string(), is_indirect(comment)));
                }
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    out
}

/// `orig -> (new_name, new_version)` for every `replace` line (`_parse_replace_block`).
fn parse_replace_block(text: &str) -> Vec<(String, (String, Option<String>))> {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out: Vec<(String, (String, Option<String>))> = Vec::new();
    let mut set = |orig: String, repl: (String, Option<String>)| {
        // Python dict assignment: last wins on duplicate keys.
        if let Some(slot) = out.iter_mut().find(|(k, _)| *k == orig) {
            slot.1 = repl;
        } else {
            out.push((orig, repl));
        }
    };
    let mut i = 0;
    while i < lines.len() {
        let stripped = lines[i].trim_end().trim_start();
        if let Some(m) = replace_single_re().captures(stripped) {
            set(m[1].to_string(), (m[2].to_string(), m.get(3).map(|g| g.as_str().to_string())));
            i += 1;
            continue;
        }
        if replace_block_open_re().is_match(stripped) {
            i += 1;
            while i < lines.len() {
                let inner = lines[i].trim_end().trim_start();
                if inner.starts_with(')') {
                    i += 1;
                    break;
                }
                if inner.is_empty() || inner.starts_with("//") {
                    i += 1;
                    continue;
                }
                if let Some(im) = replace_inner_re().captures(inner) {
                    set(im[1].to_string(), (im[2].to_string(), im.get(3).map(|g| g.as_str().to_string())));
                }
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    out
}

fn classify_pin_style(version: Option<&str>) -> PinStyle {
    let Some(version) = version else { return PinStyle::Path };
    if pseudo_version_re().is_match(version) {
        return PinStyle::Git;
    }
    if version.starts_with('v') && exact_version_re().is_match(version) {
        return PinStyle::Exact;
    }
    if exact_version_pre_re().is_match(version) {
        return PinStyle::Exact;
    }
    PinStyle::Unknown
}

fn build_purl(name: &str, version: Option<&str>) -> String {
    let base = format!("pkg:{PURL_TYPE}/{name}");
    match version {
        Some(v) => format!("{base}@{v}"),
        None => base,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_dep(
    name: &str,
    version: Option<&str>,
    direct: bool,
    declared_in: &str,
    replaced_from: Option<&str>,
    is_lockfile: bool,
) -> Option<Dependency> {
    if name.is_empty() {
        return None;
    }
    let mut reason = if is_lockfile {
        "go.sum plain-text — deterministic".to_string()
    } else {
        "go.mod plain-text grammar".to_string()
    };
    if let Some(from) = replaced_from {
        reason = format!("replace directive: {from} → {name}");
    }
    Some(Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name: name.to_string(),
        version: version.map(str::to_string),
        declared_in: declared_in.to_string(),
        scope: "main".to_string(),
        is_lockfile,
        pin_style: classify_pin_style(version),
        direct,
        purl: build_purl(name, version),
        parser_confidence: Confidence::new("high", &reason),
        declared_license: None,
        commented_out: false,
        source_kind: if is_lockfile { "lockfile" } else { "manifest" }.to_string(),
        source_extra: None,
    })
}

/// Parse a `go.mod` (`parse_manifest`): one Dependency per `require` entry,
/// applying `replace` redirects. `text` is the already-read file content.
pub fn parse_manifest(text: &str, declared_in: &str) -> Vec<Dependency> {
    let requires = parse_require_block(text);
    let replaces = parse_replace_block(text);
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for (name, version, indirect) in requires {
        let replacement = replaces.iter().find(|(k, _)| *k == name).map(|(_, v)| v);
        let dep = match replacement {
            Some((new_name, new_version)) => build_dep(
                new_name,
                new_version.as_deref(),
                !indirect,
                declared_in,
                Some(&name),
                false,
            ),
            None => build_dep(&name, Some(&version), !indirect, declared_in, None, false),
        };
        if let Some(dep) = dep {
            let k = dep.key();
            if !seen.contains(&k) {
                seen.push(k);
                out.push(dep);
            }
        }
    }
    out
}

/// Parse a `go.sum` (`parse_lockfile`): one Dependency per `(module, version)`,
/// deduped, stripping the `/go.mod` version suffix.
pub fn parse_lockfile(text: &str, declared_in: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let name = parts[0];
        let version = parts[1].strip_suffix("/go.mod").unwrap_or(parts[1]);
        if let Some(dep) = build_dep(name, Some(version), false, declared_in, None, true) {
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
    fn manifest_block_and_indirect() {
        let src = "module x\n\ngo 1.22\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n\tgithub.com/baz/qux v0.0.0-20231201120000-abcdef123456 // indirect\n)\n\nrequire github.com/single/dep v1.0.0\n";
        let deps = parse_manifest(src, "go.mod");
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "github.com/foo/bar");
        assert_eq!(deps[0].pin_style, PinStyle::Exact);
        assert!(deps[0].direct);
        // pseudo-version -> Git pin, indirect -> direct=false.
        assert_eq!(deps[1].pin_style, PinStyle::Git);
        assert!(!deps[1].direct);
    }

    #[test]
    fn replace_directive() {
        let src = "require github.com/foo/bar v1.0.0\nreplace github.com/foo/bar => github.com/me/forked v1.2.3-mine\n";
        let deps = parse_manifest(src, "go.mod");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "github.com/me/forked");
        assert_eq!(deps[0].version.as_deref(), Some("v1.2.3-mine"));
        assert!(deps[0].parser_confidence.reason.contains("replace directive"));
    }

    #[test]
    fn lockfile_dedup_and_gomod_suffix() {
        let src = "github.com/a/b v1.0.0 h1:abc\ngithub.com/a/b v1.0.0/go.mod h1:def\ngithub.com/c/d v2.0.0 h1:xyz\n";
        let deps = parse_lockfile(src, "go.sum");
        assert_eq!(deps.len(), 2);
        assert!(deps[0].is_lockfile);
    }
}
