//! Gradle `gradle.lockfile` parser — Rust port of
//! `packages/sca/parsers/gradle_lockfile.py`. Takes already-read content.

use std::collections::HashSet;

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "Maven";

const MAIN_CONFIGS: &[&str] = &[
    "compileClasspath", "runtimeClasspath", "default", "apiElements",
    "runtimeElements", "implementation", "api", "compileOnly", "runtimeOnly",
    "compile", "runtime", "providedCompile", "providedRuntime",
];
const TEST_CONFIGS: &[&str] = &[
    "testCompileClasspath", "testRuntimeClasspath", "testImplementation",
    "testCompileOnly", "testRuntimeOnly", "testApi", "testCompile", "testRuntime",
];
const BUILD_CONFIGS: &[&str] = &["annotationProcessor", "kapt", "ksp", "buildscript", "classpath"];

fn scope_from_configs(configs: &HashSet<&str>) -> &'static str {
    if configs.iter().any(|c| MAIN_CONFIGS.contains(c)) {
        "main"
    } else if configs.iter().any(|c| TEST_CONFIGS.contains(c)) {
        "test"
    } else if configs.iter().any(|c| BUILD_CONFIGS.contains(c)) {
        "build"
    } else {
        "main"
    }
}

fn parse_line(line: &str, declared_in: &str) -> Option<Dependency> {
    let (coord, configs_text) = line.split_once('=')?;
    let parts: Vec<&str> = coord.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let group = parts[0];
    let artifact = parts[1];
    let version = parts[2..].join(":");
    if group.is_empty() || artifact.is_empty() || version.is_empty() {
        return None;
    }
    let configs: HashSet<&str> = configs_text.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    let scope = scope_from_configs(&configs);
    Some(Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name: format!("{group}:{artifact}"),
        purl: format!("pkg:maven/{group}/{artifact}@{version}"),
        version: Some(version),
        declared_in: declared_in.to_string(),
        scope: scope.to_string(),
        is_lockfile: true,
        pin_style: PinStyle::Exact,
        direct: false,
        parser_confidence: Confidence::new("high", "gradle.lockfile resolved row"),
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
    })
}

/// Parse a `gradle.lockfile` (`parse`): one Dependency per `group:artifact:version=configs` row.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    for raw in content.split('\n') {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
            continue;
        }
        if let Some(d) = parse_line(line, declared_in) {
            deps.push(d);
        }
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_and_scopes() {
        let src = "# gradle lockfile\nempty=annotationProcessor\norg.springframework:spring-core:6.1.2=compileClasspath,runtimeClasspath\njunit:junit:4.13.2=testImplementation\ncom.google:kapt-dep:1.0=kapt\nmalformed:nope\n";
        let deps = parse(src, "gradle.lockfile");
        assert_eq!(deps.len(), 3);
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("org.springframework:spring-core").version.as_deref(), Some("6.1.2"));
        assert_eq!(by("org.springframework:spring-core").scope, "main");
        assert_eq!(by("org.springframework:spring-core").purl, "pkg:maven/org.springframework/spring-core@6.1.2");
        assert_eq!(by("junit:junit").scope, "test");
        assert_eq!(by("com.google:kapt-dep").scope, "build");
    }
}
