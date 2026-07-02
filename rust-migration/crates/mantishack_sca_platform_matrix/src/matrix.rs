//! Project platform-matrix aggregation — Rust port of the pure + content-based
//! parts of `packages/sca/platform_matrix/matrix.py`.
//!
//! The data structures (`PlatformPair`, `ProjectPlatformMatrix`), architecture
//! canonicalisation, and every per-file walker are ported as text-in transforms
//! (`walk_dockerfile_text`, `walk_bake_hcl_text`, `walk_bake_json_text`,
//! `walk_gha_workflow_text`, `add_runner`). The top-level `discover_platform_matrix`
//! filesystem orchestration (`rglob`, devcontainer/bake file discovery) stays in
//! Python and drives these functions with already-read content.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::glibc_db::{lookup_distro_libc, lookup_runner_libc, LibcVersion};

/// One (arch, OS-constraint) combo a Python wheel must install on
/// (`PlatformPair`). On Linux the constraint is the libc; on macOS it's the
/// macOS version; on Windows there is none.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlatformPair {
    pub arch: String,
    pub libc: Option<LibcVersion>,
    pub source: String,
    pub macos_version: Option<(u32, u32)>,
}

impl PlatformPair {
    pub fn new(arch: &str, libc: Option<LibcVersion>, source: String) -> Self {
        Self { arch: arch.to_string(), libc, source, macos_version: None }
    }

    pub fn as_str(&self) -> String {
        if let Some((maj, min)) = self.macos_version {
            return format!("{}/macos-{}.{}", self.arch, maj, min);
        }
        let libc = self.libc.as_ref().map(LibcVersion::as_str).unwrap_or_else(|| "no-libc".to_string());
        format!("{}/{}", self.arch, libc)
    }
}

/// The set of (arch, libc) pairs the project supports (`ProjectPlatformMatrix`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectPlatformMatrix {
    pub pairs: HashSet<PlatformPair>,
}

impl ProjectPlatformMatrix {
    pub fn new() -> Self {
        Self { pairs: HashSet::new() }
    }

    pub fn add(&mut self, pair: PlatformPair) {
        self.pairs.insert(pair);
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &PlatformPair> {
        self.pairs.iter()
    }
}

/// Normalise platform / arch strings to canonical names (`_canonical_arch`).
/// Unknown forms pass through unchanged.
pub fn canonical_arch(arch_ref: &str) -> &str {
    match arch_ref {
        "x86_64" | "amd64" | "linux/amd64" => "x86_64",
        "aarch64" | "arm64" | "linux/arm64" | "linux/aarch64" => "aarch64",
        "armv7l" | "armv7" | "linux/arm/v7" | "arm/v7" => "armv7l",
        "i686" | "i386" | "386" | "linux/386" => "i686",
        "ppc64le" | "linux/ppc64le" => "ppc64le",
        "s390x" | "linux/s390x" => "s390x",
        other => other,
    }
}

/// Strip digest + registry/namespace prefix to a distro-lookup key
/// (`_from_image_to_distro`). `python:3.13-bookworm@sha256:abc` →
/// `python:3.13-bookworm`; `mcr.microsoft.com/.../python:1-3.12-bookworm` →
/// `python:1-3.12-bookworm`.
pub fn from_image_to_distro(image_ref: &str) -> String {
    let ref_ = image_ref.split_once('@').map(|(h, _)| h).unwrap_or(image_ref);
    match ref_.rsplit_once('/') {
        Some((_, last)) => last.to_string(),
        None => ref_.to_string(),
    }
}

/// Split a bake `platforms = [...]` list-body into individual platform strings
/// (`_extract_platforms_from_text`). Strips `//` and `#` line comments before
/// splitting on comma, then de-quotes matched surrounding quotes.
pub fn extract_platforms_from_text(captured: &str) -> Vec<String> {
    let mut cleaned = String::new();
    for (i, line) in captured.split('\n').enumerate() {
        if i > 0 {
            cleaned.push('\n');
        }
        let mut line = line;
        if let Some((before, _)) = line.split_once("//") {
            line = before;
        }
        if let Some((before, _)) = line.split_once('#') {
            line = before;
        }
        cleaned.push_str(line);
    }

    let mut out = Vec::new();
    for raw in cleaned.split(',') {
        let mut item = raw.trim();
        let matched = (item.starts_with('"') && item.ends_with('"'))
            || (item.starts_with('\'') && item.ends_with('\''));
        if matched {
            item = if item.len() >= 2 { &item[1..item.len() - 1] } else { "" };
        }
        if !item.is_empty() {
            out.push(item.to_string());
        }
    }
    out
}

fn from_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?im)^\s*FROM\s+(?:--platform=(\S+)\s+)?(\S+)(?:\s+AS\s+\S+)?\s*$").unwrap()
    })
}

/// Parse a Dockerfile's `FROM` lines from already-read `text` and add the
/// discovered (arch, libc) pairs (`_walk_dockerfile`). `filename` is the
/// basename used in the source trace.
pub fn walk_dockerfile_text(text: &str, filename: &str, matrix: &mut ProjectPlatformMatrix) {
    for caps in from_re().captures_iter(text) {
        let platform_flag = caps.get(1).map(|m| m.as_str());
        let image_ref = caps.get(2).unwrap().as_str();
        // Skip multi-stage FROM-AS references (a prior stage name, not an image).
        if !image_ref.contains(':') && !image_ref.contains('/') {
            continue;
        }
        let distro_key = from_image_to_distro(image_ref);
        let libc = lookup_distro_libc(&distro_key);
        let archs: Vec<String> = match platform_flag {
            Some(flag) => vec![canonical_arch(flag).to_string()],
            None => vec!["x86_64".to_string(), "aarch64".to_string()],
        };
        for arch in archs {
            matrix.add(PlatformPair::new(
                &arch,
                libc.clone(),
                format!("Dockerfile FROM {image_ref} in {filename}"),
            ));
        }
    }
}

fn bake_platforms_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)platforms\s*=\s*\[([^\]]*?)\]").unwrap())
}

/// Parse a `docker-bake.hcl` body for `platforms = [...]` lists
/// (`_walk_bake_hcl`). Each entry contributes an (arch, libc=None) pair.
pub fn walk_bake_hcl_text(text: &str, filename: &str, matrix: &mut ProjectPlatformMatrix) {
    for caps in bake_platforms_re().captures_iter(text) {
        let captured = caps.get(1).unwrap().as_str();
        for platform_ref in extract_platforms_from_text(captured) {
            let arch = canonical_arch(&platform_ref);
            if arch.is_empty() {
                continue;
            }
            matrix.add(PlatformPair::new(
                arch,
                None,
                format!("docker-bake.hcl platforms in {filename}"),
            ));
        }
    }
}

/// Parse a `docker-bake.json` body: `{"target": {"<name>": {"platforms": [...]}}}`
/// (`_walk_bake_json`).
pub fn walk_bake_json_text(text: &str, filename: &str, matrix: &mut ProjectPlatformMatrix) {
    let Ok(data) = serde_json::from_str::<Value>(text) else { return };
    let Some(targets) = data.get("target").and_then(Value::as_object) else { return };
    for target_data in targets.values() {
        let Some(platforms) = target_data.get("platforms").and_then(Value::as_array) else {
            continue;
        };
        for platform_ref in platforms {
            let Some(platform_ref) = platform_ref.as_str() else { continue };
            let arch = canonical_arch(platform_ref);
            if arch.is_empty() {
                continue;
            }
            matrix.add(PlatformPair::new(
                arch,
                None,
                format!("docker-bake.json platforms in {filename}"),
            ));
        }
    }
}

const MACOS_RUNNER_LATEST: (u32, u32) = (14, 0);

fn macos_runner_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^macos-(\d+)(?:\.(\d+))?$").unwrap())
}

/// Map a GHA macOS runner label to its (major, minor) macOS version
/// (`_parse_macos_runner_version`). `None` for unrecognised labels.
pub fn parse_macos_runner_version(runner_ref: &str) -> Option<(u32, u32)> {
    if runner_ref == "macos-latest" {
        return Some(MACOS_RUNNER_LATEST);
    }
    let caps = macos_runner_re().captures(runner_ref)?;
    let major: u32 = caps.get(1).unwrap().as_str().parse().ok()?;
    let minor: u32 = caps.get(2).map(|m| m.as_str().parse().unwrap_or(0)).unwrap_or(0);
    Some((major, minor))
}

/// Resolve a GHA runner label to a `PlatformPair` and add it (`_add_runner`).
/// `workflow` is the workflow basename used in the source trace.
pub fn add_runner(runner_ref: &str, workflow: &str, matrix: &mut ProjectPlatformMatrix) {
    let libc = lookup_runner_libc(runner_ref);
    let source = format!("GHA runs-on: {runner_ref} in {workflow}");
    if runner_ref.starts_with("windows-") {
        matrix.add(PlatformPair::new("x86_64", None, source));
        return;
    }
    if runner_ref.starts_with("macos-") {
        let mut pair = PlatformPair::new("aarch64", None, source);
        pair.macos_version = parse_macos_runner_version(runner_ref);
        matrix.add(pair);
        return;
    }
    matrix.add(PlatformPair::new("x86_64", libc, source));
}

fn build_push_uses_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)^\s*-\s*uses:\s*docker/build-push-action@[^\s\n]+").unwrap()
    })
}

fn next_step_boundary_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*-\s*(?:uses|run|name):").unwrap())
}

fn platforms_input_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*platforms:\s*([^\n#]+)").unwrap())
}

fn strip_quotes(s: &str) -> &str {
    s.trim_matches(|c| c == '\'' || c == '"')
}

/// For each `docker/build-push-action` step, find the `platforms:` value inside
/// its block and lift each comma-separated arch (`_extract_gha_build_push_platforms`).
pub fn extract_gha_build_push_platforms(
    text: &str,
    workflow: &str,
    matrix: &mut ProjectPlatformMatrix,
) {
    for use_match in build_push_uses_re().find_iter(text) {
        let step_start = use_match.end();
        // Next step boundary at or after step_start (mirrors Python's pos-based
        // `re.search`, whose `^` anchors to a real line boundary >= pos).
        let step_end = next_step_boundary_re()
            .find_iter(text)
            .find(|m| m.start() >= step_start)
            .map(|m| m.start())
            .unwrap_or(text.len());
        let block = &text[step_start..step_end];
        let Some(caps) = platforms_input_re().captures(block) else { continue };
        let value = strip_quotes(caps.get(1).unwrap().as_str().trim());
        let value = value.trim_matches(|c| c == '[' || c == ']');
        for raw in value.split(',') {
            let platform_ref = strip_quotes(raw.trim());
            if platform_ref.is_empty() || platform_ref.contains("${{") {
                continue;
            }
            let arch = canonical_arch(platform_ref);
            if arch.is_empty() {
                continue;
            }
            matrix.add(PlatformPair::new(
                arch,
                None,
                format!("GHA docker/build-push-action platforms in {workflow}"),
            ));
        }
    }
}

fn runs_on_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*runs-on:\s*([^\n#]+)").unwrap())
}

fn matrix_os_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*os:\s*\[\s*([^\]]+)\s*\]").unwrap())
}

/// Walk a single GHA workflow's already-read `text` for `runs-on:` values +
/// matrix.os expansion + `docker/build-push-action` platforms
/// (`_walk_gha_workflows` per-file body). `workflow` is the basename.
pub fn walk_gha_workflow_text(text: &str, workflow: &str, matrix: &mut ProjectPlatformMatrix) {
    for m in runs_on_re().captures_iter(text) {
        let value = strip_quotes(m.get(1).unwrap().as_str().trim());
        if value.contains("${{") {
            // Variable reference — expand via matrix.os list(s).
            for mm in matrix_os_re().captures_iter(text) {
                for s in mm.get(1).unwrap().as_str().split(',') {
                    let item = strip_quotes(s.trim());
                    add_runner(item, workflow, matrix);
                }
            }
            continue;
        }
        add_runner(value, workflow, matrix);
    }
    extract_gha_build_push_platforms(text, workflow, matrix);
}

/// Whether a filename denotes a Dockerfile (`_is_dockerfile`). Takes the
/// basename; the directory walk stays call-site.
pub fn is_dockerfile(name: &str) -> bool {
    name == "Dockerfile"
        || name == "Containerfile"
        || name.starts_with("Dockerfile.")
        || name.ends_with(".dockerfile")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dump(m: &ProjectPlatformMatrix) -> Vec<(String, Option<String>, String, Option<(u32, u32)>)> {
        let mut v: Vec<_> = m
            .iter()
            .map(|p| (p.arch.clone(), p.libc.as_ref().map(|l| l.as_str()), p.source.clone(), p.macos_version))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn canonical_arch_aliases() {
        assert_eq!(canonical_arch("amd64"), "x86_64");
        assert_eq!(canonical_arch("linux/arm64"), "aarch64");
        assert_eq!(canonical_arch("arm/v7"), "armv7l");
        assert_eq!(canonical_arch("386"), "i686");
        assert_eq!(canonical_arch("linux/ppc64le"), "ppc64le");
        assert_eq!(canonical_arch("s390x"), "s390x");
        assert_eq!(canonical_arch("weird"), "weird");
    }

    #[test]
    fn from_image_forms() {
        assert_eq!(from_image_to_distro("python:3.13-bookworm@sha256:abc"), "python:3.13-bookworm");
        assert_eq!(from_image_to_distro("debian:bookworm"), "debian:bookworm");
        assert_eq!(
            from_image_to_distro("mcr.microsoft.com/devcontainers/python:1-3.12-bookworm"),
            "python:1-3.12-bookworm"
        );
        assert_eq!(from_image_to_distro("alpine"), "alpine");
        assert_eq!(from_image_to_distro("foo/bar/baz:tag"), "baz:tag");
    }

    #[test]
    fn extract_platforms() {
        assert_eq!(extract_platforms_from_text(r#""linux/amd64", "linux/arm64""#), vec!["linux/amd64", "linux/arm64"]);
        assert_eq!(
            extract_platforms_from_text("\"linux/amd64\", // x86\n \"linux/arm64\", # arm\n"),
            vec!["linux/amd64", "linux/arm64"]
        );
        assert_eq!(extract_platforms_from_text("'linux/amd64',''"), vec!["linux/amd64"]);
        assert!(extract_platforms_from_text("  ,  ").is_empty());
    }

    #[test]
    fn macos_versions() {
        assert_eq!(parse_macos_runner_version("macos-latest"), Some((14, 0)));
        assert_eq!(parse_macos_runner_version("macos-13"), Some((13, 0)));
        assert_eq!(parse_macos_runner_version("macos-14.5"), Some((14, 5)));
        assert_eq!(parse_macos_runner_version("macos-15"), Some((15, 0)));
        assert_eq!(parse_macos_runner_version("macos"), None);
        assert_eq!(parse_macos_runner_version("macos-x"), None);
        assert_eq!(parse_macos_runner_version("macos-13.0"), Some((13, 0)));
    }

    #[test]
    fn dockerfile_names() {
        for (n, want) in [
            ("Dockerfile", true), ("Containerfile", true), ("Dockerfile.dev", true),
            ("app.dockerfile", true), ("dockerfile", false), ("Foo", false),
            ("Dockerfile.", true), ("x.Dockerfile", false),
        ] {
            assert_eq!(is_dockerfile(n), want, "{n}");
        }
    }

    #[test]
    fn walk_dockerfile_cases() {
        let mut m = ProjectPlatformMatrix::new();
        walk_dockerfile_text("FROM --platform=linux/arm64 python:3.12-bookworm AS build\n", "Dockerfile", &mut m);
        assert_eq!(dump(&m), vec![
            ("aarch64".into(), Some("glibc 2.36".into()),
             "Dockerfile FROM python:3.12-bookworm in Dockerfile".into(), None),
        ]);

        let mut m = ProjectPlatformMatrix::new();
        walk_dockerfile_text("FROM debian:bullseye\n", "Dockerfile", &mut m);
        assert_eq!(m.len(), 2);
        assert!(m.iter().all(|p| p.libc.as_ref().unwrap().as_str() == "glibc 2.31"));

        // Unknown image -> both arches, libc None.
        let mut m = ProjectPlatformMatrix::new();
        walk_dockerfile_text("FROM myregistry/custom:tag\n", "Dockerfile", &mut m);
        assert_eq!(m.len(), 2);
        assert!(m.iter().all(|p| p.libc.is_none()));

        // Bare stage name (no ':' no '/') is skipped.
        let mut m = ProjectPlatformMatrix::new();
        walk_dockerfile_text("FROM build\nFROM python:3.11-bookworm\n", "Dockerfile", &mut m);
        assert_eq!(m.len(), 2);
        assert!(m.iter().all(|p| p.source.contains("python:3.11-bookworm")));
    }

    #[test]
    fn add_runner_cases() {
        let mut m = ProjectPlatformMatrix::new();
        add_runner("ubuntu-22.04", "ci.yml", &mut m);
        assert_eq!(dump(&m), vec![
            ("x86_64".into(), Some("glibc 2.35".into()), "GHA runs-on: ubuntu-22.04 in ci.yml".into(), None),
        ]);

        let mut m = ProjectPlatformMatrix::new();
        add_runner("windows-latest", "ci.yml", &mut m);
        assert_eq!(dump(&m), vec![
            ("x86_64".into(), None, "GHA runs-on: windows-latest in ci.yml".into(), None),
        ]);

        let mut m = ProjectPlatformMatrix::new();
        add_runner("macos-14", "ci.yml", &mut m);
        assert_eq!(dump(&m), vec![
            ("aarch64".into(), None, "GHA runs-on: macos-14 in ci.yml".into(), Some((14, 0))),
        ]);
        assert_eq!(m.iter().next().unwrap().as_str(), "aarch64/macos-14.0");

        let mut m = ProjectPlatformMatrix::new();
        add_runner("unknown-runner", "ci.yml", &mut m);
        assert_eq!(dump(&m), vec![
            ("x86_64".into(), None, "GHA runs-on: unknown-runner in ci.yml".into(), None),
        ]);
    }

    #[test]
    fn gha_build_push_cases() {
        let basic = "      - uses: docker/build-push-action@v5\n        with:\n          platforms: linux/amd64,linux/arm64\n      - uses: other\n";
        let mut m = ProjectPlatformMatrix::new();
        extract_gha_build_push_platforms(basic, "rel.yml", &mut m);
        assert_eq!(m.len(), 2);
        assert!(m.iter().all(|p| p.source == "GHA docker/build-push-action platforms in rel.yml"));

        let inline = "      - uses: docker/build-push-action@v5\n        with:\n          platforms: [linux/amd64, linux/arm64]\n";
        let mut m = ProjectPlatformMatrix::new();
        extract_gha_build_push_platforms(inline, "rel.yml", &mut m);
        assert_eq!(m.len(), 2);

        let var = "      - uses: docker/build-push-action@v5\n        with:\n          platforms: ${{ matrix.p }}\n";
        let mut m = ProjectPlatformMatrix::new();
        extract_gha_build_push_platforms(var, "rel.yml", &mut m);
        assert!(m.is_empty());
    }

    #[test]
    fn bake_cases() {
        let hcl = "target \"x\" {\n platforms = [\n  \"linux/amd64\",\n  \"linux/arm64\",\n ]\n}\n";
        let mut m = ProjectPlatformMatrix::new();
        walk_bake_hcl_text(hcl, "docker-bake.hcl", &mut m);
        assert_eq!(m.len(), 2);
        assert!(m.iter().all(|p| p.source == "docker-bake.hcl platforms in docker-bake.hcl"));

        let json = r#"{"target":{"x":{"platforms":["linux/amd64","linux/arm64"]}}}"#;
        let mut m = ProjectPlatformMatrix::new();
        walk_bake_json_text(json, "docker-bake.json", &mut m);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn gha_workflow_matrix_os() {
        let wf = "jobs:\n  build:\n    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-22.04, ubuntu-24.04]\n";
        let mut m = ProjectPlatformMatrix::new();
        walk_gha_workflow_text(wf, "ci.yml", &mut m);
        let libcs: HashSet<_> = m.iter().map(|p| p.libc.as_ref().unwrap().as_str()).collect();
        assert_eq!(libcs, HashSet::from(["glibc 2.35".to_string(), "glibc 2.39".to_string()]));
    }
}
