//! uv `uv.lock` parser — Rust port of `packages/sca/parsers/uv_lock.py`.
//! Takes already-read content.

use serde_json::{Map, Value};

use crate::models::{Confidence, Dependency, PinStyle};
use crate::toml_util::parse_toml;

const ECOSYSTEM: &str = "PyPI";

fn build_dep(pkg: &Value, declared_in: &str) -> Option<Dependency> {
    let obj = pkg.as_object()?;
    let name = obj.get("name").and_then(Value::as_str)?.trim();
    let version = obj.get("version").and_then(Value::as_str)?.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    let empty = Map::new();
    let source = obj.get("source").and_then(Value::as_object).unwrap_or(&empty);
    // Skip the project's own (virtual) row + local editables/directories.
    if ["virtual", "editable", "directory"].iter().any(|k| source.contains_key(*k)) {
        return None;
    }
    let pin_style = if source.contains_key("git") { PinStyle::Git } else { PinStyle::Exact };
    Some(Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name: name.to_string(),
        version: Some(version.to_string()),
        declared_in: declared_in.to_string(),
        scope: "main".to_string(),
        is_lockfile: true,
        pin_style,
        direct: false,
        purl: format!("pkg:pypi/{name}@{version}"),
        parser_confidence: Confidence::new("high", "uv.lock pinned dependency"),
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
        source_extra: None,
    })
}

/// Parse a `uv.lock` (`parse`): one Dependency per registry `[[package]]`.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Some(data) = parse_toml(content) else { return Vec::new() };
    let Some(packages) = data.get("package").and_then(Value::as_array) else { return Vec::new() };
    packages.iter().filter_map(|pkg| build_dep(pkg, declared_in)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uv_entries() {
        let src = r#"
[[package]]
name = "myproject"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "requests"
version = "2.28.0"

[[package]]
name = "gitdep"
version = "1.0.0"
source = { git = "https://github.com/x/y" }

[[package]]
name = "localdep"
version = "1.0.0"
source = { editable = "./local" }
"#;
        let deps = parse(src, "uv.lock");
        // virtual + editable skipped; requests + gitdep remain.
        assert_eq!(deps.len(), 2);
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("requests").pin_style, PinStyle::Exact);
        assert_eq!(by("requests").purl, "pkg:pypi/requests@2.28.0");
        assert_eq!(by("gitdep").pin_style, PinStyle::Git);
        assert!(deps.iter().all(|d| d.name != "myproject" && d.name != "localdep"));
    }
}
