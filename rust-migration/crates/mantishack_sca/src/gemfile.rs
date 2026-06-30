//! Ruby Gemfile parser — Rust port of `packages/sca/parsers/gemfile.py`.
//!
//! The Python regexes use a backreference (`(?P=quote)`) and a lookbehind
//! (`(?<!\\)#`) that Rust's `regex` crate doesn't support; both are rewritten
//! to equivalent quote-alternation / manual-scan forms.

use std::sync::OnceLock;

use regex::Regex;

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "RubyGems";
const PURL_TYPE: &str = "gem";

// `gem '<name>'` / `gem "<name>"` + optional tail (quote backreference rewritten
// as a single/double alternation).
fn gem_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"^\s*gem\s+(?:'([A-Za-z0-9_.\-]+)'|"([A-Za-z0-9_.\-]+)")([^\n#]*)"#).unwrap()
    })
}

// Each `'<op> <ver>'` token (quote backreference rewritten as alternation).
fn version_spec_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"'\s*(=|>=|<=|>|<|~>|\^)?\s*([\w.\-+]+)\s*'|"\s*(=|>=|<=|>|<|~>|\^)?\s*([\w.\-+]+)\s*""#).unwrap()
    })
}

fn control_flow_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*(if|unless|case|while)\b").unwrap())
}
fn git_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\bgit\s*:\s*['"]"#).unwrap())
}
fn github_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\bgithub\s*:\s*['"]"#).unwrap())
}
fn path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\bpath\s*:\s*['"]"#).unwrap())
}
fn lock_row_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^    (\S+)\s+\(([^)]+)\)\s*$").unwrap())
}

/// `re.split(r"(?<!\\)#", line, maxsplit=1)[0]` — text before the first
/// unescaped `#`.
fn strip_trailing_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'#' && (i == 0 || bytes[i - 1] != b'\\') {
            return &line[..i];
        }
    }
    line
}

fn build_purl(name: &str, version: Option<&str>) -> String {
    let base = format!("pkg:{PURL_TYPE}/{name}");
    match version {
        Some(v) => format!("{base}@{v}"),
        None => base,
    }
}

fn starts_with_digit(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_digit())
}

fn parse_version_specs(rest: &str) -> (PinStyle, Option<String>) {
    let caps: Vec<_> = version_spec_re().captures_iter(rest).collect();
    if caps.is_empty() {
        return (PinStyle::Wildcard, None);
    }
    if caps.len() > 1 {
        return (PinStyle::Range, None);
    }
    let c = &caps[0];
    // Single-quote alternative populates groups 1/2; double-quote 3/4.
    let (op, ver) = if let Some(v) = c.get(2) {
        (c.get(1).map_or("=", |m| m.as_str()), v.as_str())
    } else {
        (c.get(3).map_or("=", |m| m.as_str()), c.get(4).map_or("", |m| m.as_str()))
    };
    if !starts_with_digit(ver) {
        return (PinStyle::Wildcard, None);
    }
    let pin = match op {
        "=" => PinStyle::Exact,
        "~>" => PinStyle::Tilde,
        "^" => PinStyle::Caret,
        _ => PinStyle::Range,
    };
    (pin, Some(ver.to_string()))
}

fn build_dep(name: &str, rest: &str, declared_in: &str, confidence_level: &str, reason: &str) -> Dependency {
    let rest_clean = rest.trim().trim_start_matches(',').trim();
    // git: / github: -> Git, path: -> Path, else version specs.
    let (pin_style, version) = if git_re().is_match(rest_clean) || github_re().is_match(rest_clean) {
        (PinStyle::Git, None)
    } else if path_re().is_match(rest_clean) {
        (PinStyle::Path, None)
    } else {
        parse_version_specs(rest_clean)
    };
    Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name: name.to_string(),
        version: version.clone(),
        declared_in: declared_in.to_string(),
        scope: "main".to_string(),
        is_lockfile: false,
        pin_style,
        direct: true,
        purl: build_purl(name, version.as_deref()),
        parser_confidence: Confidence::new(confidence_level, reason),
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
    }
}

/// Parse a `Gemfile`, one Dependency per `gem` line (`parse_manifest`).
pub fn parse_manifest(text: &str, declared_in: &str) -> Vec<Dependency> {
    let has_control_flow = control_flow_re().is_match(text);
    let confidence_level = if has_control_flow { "medium" } else { "high" };
    let reason = if has_control_flow {
        "Gemfile DSL — heuristic regex"
    } else {
        "Gemfile DSL — straight-line script"
    };
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        if raw.trim_start().starts_with('#') {
            continue;
        }
        let line = strip_trailing_comment(raw);
        let Some(m) = gem_line_re().captures(line) else { continue };
        let name = m.get(1).or_else(|| m.get(2)).map_or("", |g| g.as_str());
        let rest = m.get(3).map_or("", |g| g.as_str());
        let dep = build_dep(name, rest, declared_in, confidence_level, reason);
        let k = dep.key();
        if !seen.contains(&k) {
            seen.push(k);
            out.push(dep);
        }
    }
    out
}

/// Parse a `Gemfile.lock` GEM section, one Dependency per resolved gem
/// (`parse_lockfile`).
pub fn parse_lockfile(text: &str, declared_in: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut in_specs = false;
    for raw in text.split('\n') {
        let line = raw.trim_end();
        if line.trim_start().starts_with("specs:") {
            in_specs = true;
            continue;
        }
        if !in_specs {
            continue;
        }
        if !line.is_empty() && !line.starts_with(' ') {
            in_specs = false;
            continue;
        }
        let Some(m) = lock_row_re().captures(line) else { continue };
        let name = m[1].to_string();
        let version = m[2].trim().to_string();
        if !starts_with_digit(&version) {
            continue;
        }
        let dep = Dependency {
            ecosystem: ECOSYSTEM.to_string(),
            name: name.clone(),
            purl: build_purl(&name, Some(&version)),
            version: Some(version),
            declared_in: declared_in.to_string(),
            scope: "main".to_string(),
            is_lockfile: true,
            pin_style: PinStyle::Exact,
            direct: false,
            parser_confidence: Confidence::new("high", "Gemfile.lock plain-text — deterministic structure"),
            declared_license: None,
            commented_out: false,
            source_kind: "lockfile".to_string(),
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

    #[test]
    fn manifest_versions_and_overrides() {
        let src = "source 'https://rubygems.org'\ngem 'rails', '~> 7.1.2'\ngem \"pg\", '>= 1.0', '< 2.0'  # comment\ngem 'puma'\ngem 'mygem', git: 'https://github.com/x/y'\ngem 'localdep', path: '../local'\n";
        let deps = parse_manifest(src, "Gemfile");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("rails").pin_style, PinStyle::Tilde);
        assert_eq!(by("rails").version.as_deref(), Some("7.1.2"));
        assert_eq!(by("pg").pin_style, PinStyle::Range); // two specs
        assert_eq!(by("puma").pin_style, PinStyle::Wildcard);
        assert_eq!(by("mygem").pin_style, PinStyle::Git);
        assert_eq!(by("localdep").pin_style, PinStyle::Path);
        // straight-line script -> high confidence.
        assert_eq!(by("rails").parser_confidence.level, "high");
    }

    #[test]
    fn control_flow_lowers_confidence() {
        let src = "if RUBY_VERSION > '3'\n  gem 'rails', '7.1.2'\nend\n";
        let deps = parse_manifest(src, "Gemfile");
        assert_eq!(deps[0].parser_confidence.level, "medium");
    }

    #[test]
    fn lockfile_specs_block() {
        let src = "GEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (7.1.2)\n      activesupport (= 7.1.2)\n    rack (>= 2.2.4)\n\nPLATFORMS\n  ruby\n";
        let deps = parse_lockfile(src, "Gemfile.lock");
        // Only the 4-space top-level rows; the 6-space runtime dep is skipped.
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "actionpack");
        assert_eq!(deps[0].version.as_deref(), Some("7.1.2"));
        assert!(deps[0].is_lockfile);
    }
}
