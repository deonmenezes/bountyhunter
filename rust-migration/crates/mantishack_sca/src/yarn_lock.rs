//! Yarn `yarn.lock` parser — Rust port of `packages/sca/parsers/yarn_lock.py`.
//! Handles both classic v1 (line-oriented text) and Berry (YAML). Takes
//! already-read content.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "npm";

fn quoted_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#""([^"]*)""#).unwrap())
}
fn prop_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^([A-Za-z_][\w-]*)\s+(?:"([^"]*)"|([^\s].*))$"#).unwrap())
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
        PinStyle::Git => Confidence::new("medium", "yarn.lock git source"),
        PinStyle::Path => Confidence::new("medium", "yarn.lock workspace/file source"),
        _ if version.is_none() => Confidence::new("low", "yarn.lock entry without version"),
        _ => Confidence::new("high", "yarn.lock resolved entry"),
    }
}

fn name_from_descriptor(descriptor: &str) -> Option<String> {
    let s = descriptor.trim().trim_matches('"');
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('@') {
        let _ = rest;
        let slash = s.find('/')?;
        match s[slash..].find('@') {
            Some(rel) => Some(s[..slash + rel].to_string()),
            None => Some(s.to_string()),
        }
    } else {
        match s.find('@') {
            Some(sep) => Some(s[..sep].to_string()),
            None => Some(s.to_string()),
        }
    }
}

fn pin_from_resolved(resolved: &str, version: Option<&str>) -> PinStyle {
    if resolved.starts_with("git+") || resolved.starts_with("git:") || resolved.starts_with("git@") {
        PinStyle::Git
    } else if resolved.starts_with("file:") {
        PinStyle::Path
    } else if version.is_some() {
        PinStyle::Exact
    } else {
        PinStyle::Wildcard
    }
}

fn pin_from_berry_resolution(resolution: Option<&str>, version: Option<&str>) -> PinStyle {
    if let Some(r) = resolution {
        if r.contains("@git+") || r.ends_with("@git") {
            return PinStyle::Git;
        }
        if r.contains("@workspace:") || r.contains("@portal:") || r.contains("@file:") {
            return PinStyle::Path;
        }
    }
    if version.is_some() {
        PinStyle::Exact
    } else {
        PinStyle::Wildcard
    }
}

fn make_dep(name: &str, version: Option<&str>, pin_style: PinStyle, declared_in: &str) -> Dependency {
    Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name: name.to_string(),
        version: version.map(str::to_string),
        declared_in: declared_in.to_string(),
        scope: "main".to_string(),
        is_lockfile: true,
        pin_style,
        direct: false,
        purl: build_purl(name, version),
        parser_confidence: confidence(pin_style, version),
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
        source_extra: None,
    }
}

fn split_classic_specs(line: &str) -> Vec<String> {
    if line.contains('"') {
        quoted_re().captures_iter(line).map(|c| c[1].to_string()).collect()
    } else {
        line.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
    }
}

fn parse_classic_prop(line: &str) -> (Option<String>, String) {
    match prop_re().captures(line) {
        Some(m) => {
            let key = m[1].to_string();
            let value = m.get(2).or_else(|| m.get(3)).map_or("", |g| g.as_str());
            (Some(key), value.trim().to_string())
        }
        None => (None, String::new()),
    }
}

fn from_classic_block(specs: &[String], props: &HashMap<String, String>, declared_in: &str) -> Option<Dependency> {
    let name = specs.first().and_then(|s| name_from_descriptor(s))?;
    if name.is_empty() {
        return None;
    }
    let version = props.get("version").filter(|v| !v.is_empty()).cloned();
    let resolved = props.get("resolved").map_or("", String::as_str);
    let pin_style = pin_from_resolved(resolved, version.as_deref());
    Some(make_dep(&name, version.as_deref(), pin_style, declared_in))
}

fn looks_like_berry(text: &str) -> bool {
    let head: String = text.split('\n').take(30).collect::<Vec<_>>().join("\n");
    if head.contains("__metadata:") {
        return true;
    }
    if head.contains("# yarn lockfile v1") {
        return false;
    }
    if let Ok(data) = serde_yaml::from_str::<Value>(text) {
        if data.as_object().map(|o| o.contains_key("__metadata")).unwrap_or(false) {
            return true;
        }
    }
    false
}

fn parse_classic(text: &str, declared_in: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut current_specs: Vec<String> = Vec::new();
    let mut current_props: HashMap<String, String> = HashMap::new();

    for raw in text.split('\n') {
        let stripped = raw.trim();
        if stripped.is_empty() || raw.trim_start().starts_with('#') {
            if !current_specs.is_empty() && stripped.is_empty() {
                if let Some(d) = from_classic_block(&current_specs, &current_props, declared_in) {
                    deps.push(d);
                }
                current_specs.clear();
                current_props.clear();
            }
            continue;
        }
        let first = raw.chars().next();
        if first != Some(' ') && first != Some('\t') {
            if let Some(d) = from_classic_block(&current_specs, &current_props, declared_in) {
                deps.push(d);
            }
            current_specs = split_classic_specs(raw.trim_end_matches(':').trim_end());
            current_props.clear();
        } else if let (Some(key), value) = parse_classic_prop(raw.trim()) {
            current_props.insert(key, value);
        }
    }
    if let Some(d) = from_classic_block(&current_specs, &current_props, declared_in) {
        deps.push(d);
    }
    deps
}

fn parse_berry(text: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_yaml::from_str::<Value>(text) else { return Vec::new() };
    let Some(obj) = data.as_object() else { return Vec::new() };
    let mut deps = Vec::new();
    for (descriptor, entry) in obj {
        if descriptor == "__metadata" {
            continue;
        }
        let Some(entry) = entry.as_object() else { continue };
        let first_descriptor = descriptor.split(',').next().unwrap_or("").trim();
        let Some(name) = name_from_descriptor(first_descriptor) else { continue };
        let version = entry.get("version").and_then(Value::as_str);
        let resolution = entry.get("resolution").and_then(Value::as_str);
        let pin_style = pin_from_berry_resolution(resolution, version);
        deps.push(make_dep(&name, version, pin_style, declared_in));
    }
    deps
}

/// Parse a `yarn.lock` (`parse`): Berry (YAML) or classic v1 by format sniff.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    if looks_like_berry(content) {
        parse_berry(content, declared_in)
    } else {
        parse_classic(content, declared_in)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_v1() {
        let src = "# yarn lockfile v1\n\n\nlodash@^4.17.21:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n\n\"@types/node@^20.10.0\":\n  version \"20.10.5\"\n\ngitpkg@git+https://github.com/x/y.git:\n  version \"1.0.0\"\n  resolved \"git+https://github.com/x/y.git#abc\"\n";
        let deps = parse(src, "yarn.lock");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("lodash").version.as_deref(), Some("4.17.21"));
        assert_eq!(by("lodash").pin_style, PinStyle::Exact);
        assert_eq!(by("@types/node").version.as_deref(), Some("20.10.5"));
        assert_eq!(by("gitpkg").pin_style, PinStyle::Git);
    }

    #[test]
    fn berry_yaml() {
        let src = "__metadata:\n  version: 6\n\n\"lodash@npm:^4.17.21\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n\n\"mypkg@workspace:./pkgs/x\":\n  version: 0.0.0-use.local\n  resolution: \"mypkg@workspace:./pkgs/x\"\n";
        let deps = parse(src, "yarn.lock");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("lodash").version.as_deref(), Some("4.17.21"));
        assert_eq!(by("lodash").pin_style, PinStyle::Exact);
        assert_eq!(by("mypkg").pin_style, PinStyle::Path); // workspace
    }
}
