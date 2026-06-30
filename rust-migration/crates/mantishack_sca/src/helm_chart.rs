//! Helm Chart parser — Rust port of `packages/sca/parsers/helm_chart.py`
//! (`parse`). Parses `Chart.yaml` / `Chart.lock` `dependencies`. Takes
//! already-read content; `is_lockfile` is derived from the `Chart.lock`
//! basename of `declared_in`. (`chart_repository_hosts` is a filesystem walk,
//! not ported.)

use serde_json::{json, Value};

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "Helm";
const PURL_TYPE: &str = "helm";

fn classify_version(version: &str) -> PinStyle {
    if matches!(version, "*" | "x" | "X" | "latest") {
        return PinStyle::Wildcard;
    }
    if version.starts_with('^') {
        return PinStyle::Caret;
    }
    if version.starts_with('~') {
        return PinStyle::Tilde;
    }
    if version.contains('<') || version.contains('>') || version.contains('=') || version.contains(" - ") {
        return PinStyle::Range;
    }
    if version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return PinStyle::Exact;
    }
    PinStyle::Unknown
}

fn build_dep(entry: &Value, declared_in: &str, is_lockfile: bool) -> Option<Dependency> {
    let obj = entry.as_object()?;
    let name = obj.get("name").and_then(Value::as_str)?.trim();
    let version = obj.get("version").and_then(Value::as_str)?.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    let repository = obj.get("repository").and_then(Value::as_str).unwrap_or("");
    let pin_style = classify_version(version);
    let (level, reason) = if is_lockfile {
        ("high", "Chart.lock pinned dependency".to_string())
    } else {
        let repo_disp = if repository.is_empty() { "unspecified" } else { repository };
        ("medium", format!("Chart.yaml dependency entry (repository: {repo_disp})"))
    };
    let source_extra = if repository.is_empty() { None } else { Some(json!({"repository": repository})) };
    Some(Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name: name.to_string(),
        version: Some(version.to_string()),
        declared_in: declared_in.to_string(),
        scope: "main".to_string(),
        is_lockfile,
        pin_style,
        direct: !is_lockfile,
        purl: format!("pkg:{PURL_TYPE}/{name}@{version}"),
        parser_confidence: Confidence::new(level, &reason),
        declared_license: None,
        commented_out: false,
        source_kind: "helm_chart".to_string(),
        source_extra,
    })
}

/// Parse a `Chart.yaml`/`Chart.lock` (`parse`): one Dependency per dependency.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_yaml::from_str::<Value>(content) else { return Vec::new() };
    let Some(deps_raw) = data.get("dependencies").and_then(Value::as_array) else { return Vec::new() };
    let basename = declared_in.rsplit(['/', '\\']).next().unwrap_or(declared_in);
    let is_lockfile = basename == "Chart.lock";
    deps_raw.iter().filter_map(|e| build_dep(e, declared_in, is_lockfile)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chart_yaml_deps() {
        let src = "apiVersion: v2\nname: mychart\ndependencies:\n  - name: postgresql\n    version: ^13.4.2\n    repository: https://charts.bitnami.com/bitnami\n  - name: redis\n    version: 17.0.0\n  - name: nginx\n    version: \"*\"\n  - name: ranged\n    version: \">=1.0.0 <2.0.0\"\n";
        let deps = parse(src, "Chart.yaml");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("postgresql").pin_style, PinStyle::Caret);
        assert_eq!(by("postgresql").source_extra.as_ref().unwrap()["repository"], "https://charts.bitnami.com/bitnami");
        assert!(!by("postgresql").is_lockfile);
        assert_eq!(by("redis").pin_style, PinStyle::Exact);
        assert_eq!(by("nginx").pin_style, PinStyle::Wildcard);
        assert_eq!(by("ranged").pin_style, PinStyle::Range);
    }

    #[test]
    fn chart_lock_is_lockfile() {
        let src = "dependencies:\n  - name: postgresql\n    version: 13.4.2\n    repository: https://x\n";
        let deps = parse(src, "subchart/Chart.lock");
        assert!(deps[0].is_lockfile);
        assert!(!deps[0].direct);
        assert_eq!(deps[0].parser_confidence.reason, "Chart.lock pinned dependency");
    }
}
