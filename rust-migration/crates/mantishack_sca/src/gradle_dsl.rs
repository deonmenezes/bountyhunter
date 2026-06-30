//! Gradle DSL parser — Rust port of `packages/sca/parsers/gradle_dsl.py`
//! (the inline single-string + named-args forms). Form 3 (version-catalog
//! accessors `libs.x.y`) resolves through `gradle/libs.versions.toml` on the
//! filesystem and is left to the caller. Takes already-read content. The Python
//! backreference regexes (`(?P=quote)`) are rewritten to quote-alternation.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::json;

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "Maven";
const PURL_TYPE: &str = "maven";

const CONFIG_TO_SCOPE: &[(&str, &str)] = &[
    ("implementation", "main"), ("api", "main"), ("compileOnly", "main"),
    ("runtimeOnly", "main"), ("compile", "main"), ("runtime", "main"),
    ("kapt", "build"), ("ksp", "build"), ("annotationProcessor", "build"),
    ("testImplementation", "test"), ("testApi", "test"),
    ("testCompileOnly", "test"), ("testRuntimeOnly", "test"),
    ("androidTestImplementation", "test"),
];

fn config_to_scope(config: &str) -> Option<&'static str> {
    CONFIG_TO_SCOPE.iter().find(|(k, _)| *k == config).map(|(_, v)| *v)
}

fn single_string_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b([a-zA-Z]+)\s*\(?\s*(?:'([A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+(?::[^']+)?)'|"([A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+(?::[^"]+)?)")"#,
        )
        .unwrap()
    })
}
fn named_args_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b([a-zA-Z]+)\s*\(?\s*group\s*:\s*(?:'([^']+)'|"([^"]+)")\s*,\s*name\s*:\s*(?:'([^']+)'|"([^"]+)")\s*(?:,\s*version\s*:\s*(?:'([^']+)'|"([^"]+)")\s*)?"#,
        )
        .unwrap()
    })
}

fn classify_version(version: Option<&str>) -> PinStyle {
    let Some(v) = version else { return PinStyle::Wildcard };
    if v.contains('$') {
        PinStyle::Unknown // ${...} interpolation — unresolvable
    } else if v.starts_with('[')
        || v.starts_with('(')
        || (v.contains('+') && v.ends_with('+')) // dynamic 1.+
        || v.ends_with("-SNAPSHOT")
        || v == "latest.release"
    {
        PinStyle::Range
    } else {
        PinStyle::Exact
    }
}

fn build_purl(group: &str, name: &str, version: Option<&str>) -> String {
    let base = format!("pkg:{PURL_TYPE}/{group}/{name}");
    match version {
        Some(v) => format!("{base}@{v}"),
        None => base,
    }
}

fn build_dep(group: &str, name: &str, version: Option<&str>, scope: &str, declared_in: &str) -> Dependency {
    Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name: format!("{group}/{name}"),
        version: version.map(str::to_string),
        declared_in: declared_in.to_string(),
        scope: scope.to_string(),
        is_lockfile: false,
        pin_style: classify_version(version),
        direct: true,
        purl: build_purl(group, name, version),
        parser_confidence: Confidence::new(
            "medium",
            "Gradle DSL — heuristic regex parse (Turing-complete script not executed)",
        ),
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
        source_extra: Some(json!({"origin": "gradle_inline"})),
    }
}

fn push_dep(dep: Dependency, out: &mut Vec<Dependency>, seen: &mut Vec<String>) {
    let k = dep.key();
    if !seen.contains(&k) {
        seen.push(k);
        out.push(dep);
    }
}

/// Parse a `build.gradle(.kts)` (`parse`): single-string + named-args deps.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    for m in single_string_re().captures_iter(content) {
        let Some(scope) = config_to_scope(&m[1]) else { continue };
        let coord = m.get(2).or_else(|| m.get(3)).unwrap().as_str();
        let parts: Vec<&str> = coord.split(':').collect();
        if parts.len() < 2 {
            continue;
        }
        let version = parts.get(2).copied();
        push_dep(build_dep(parts[0], parts[1], version, scope, declared_in), &mut out, &mut seen);
    }
    for m in named_args_re().captures_iter(content) {
        let Some(scope) = config_to_scope(&m[1]) else { continue };
        let group = m.get(2).or_else(|| m.get(3)).unwrap().as_str();
        let name = m.get(4).or_else(|| m.get(5)).unwrap().as_str();
        let version = m.get(6).or_else(|| m.get(7)).map(|x| x.as_str());
        push_dep(build_dep(group, name, version, scope, declared_in), &mut out, &mut seen);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gradle_inline_forms() {
        let src = "dependencies {\n    implementation 'org.springframework:spring-core:6.1.2'\n    testImplementation(\"junit:junit:4.13.2\")\n    api group: 'com.google.guava', name: 'guava', version: '33.0.0'\n    implementation 'no.version:lib'\n    implementation 'dyn:dep:1.+'\n    runtimeOnly 'snap:shot:1.0-SNAPSHOT'\n    notaconfig 'x:y:1.0'\n}\n";
        let deps = parse(src, "build.gradle");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("org.springframework/spring-core").version.as_deref(), Some("6.1.2"));
        assert_eq!(by("org.springframework/spring-core").pin_style, PinStyle::Exact);
        assert_eq!(by("junit/junit").scope, "test");
        // named-args form.
        assert_eq!(by("com.google.guava/guava").version.as_deref(), Some("33.0.0"));
        assert_eq!(by("no.version/lib").pin_style, PinStyle::Wildcard);
        assert_eq!(by("dyn/dep").pin_style, PinStyle::Range); // 1.+
        assert_eq!(by("snap/shot").pin_style, PinStyle::Range); // -SNAPSHOT
        // unknown config skipped.
        assert!(deps.iter().all(|d| d.name != "x/y"));
    }
}
