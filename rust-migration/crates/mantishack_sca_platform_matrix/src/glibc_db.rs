//! Distro-image → libc version lookup tables — Rust port of
//! `packages/sca/platform_matrix/glibc_db.py`.
//!
//! Two families: `glibc` (Debian/Ubuntu/Fedora/RHEL derivatives) and `musl`
//! (Alpine). Both family and version matter for wheel compatibility
//! (`manylinux_2_38` needs glibc ≥ 2.38; `musllinux_1_2` needs musl ≥ 1.2).
//! Unknown images return `None` rather than guess.

use std::collections::HashMap;
use std::sync::OnceLock;

/// A libc family + version pair, e.g. `LibcVersion { family: "glibc", version: [2, 36] }`.
/// Versions are component vectors for lexical comparison (`[2, 36] < [2, 39]`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LibcVersion {
    pub family: String,
    pub version: Vec<u32>,
}

impl LibcVersion {
    pub fn new(family: &str, version: &[u32]) -> Self {
        Self { family: family.to_string(), version: version.to_vec() }
    }

    /// `as_str`: `"{family} {v0.v1.…}"`.
    pub fn as_str(&self) -> String {
        let joined = self
            .version
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(".");
        format!("{} {}", self.family, joined)
    }
}

// Distro release → libc family + version, in declaration order (matches the
// Python dict; `known_distros` preserves it). Format: "distro:codename".
const DISTRO_LIBC: &[(&str, &str, &[u32])] = &[
    // Debian
    ("debian:buster", "glibc", &[2, 28]),
    ("debian:bullseye", "glibc", &[2, 31]),
    ("debian:bookworm", "glibc", &[2, 36]),
    ("debian:trixie", "glibc", &[2, 39]),
    // Ubuntu
    ("ubuntu:20.04", "glibc", &[2, 31]),
    ("ubuntu:focal", "glibc", &[2, 31]),
    ("ubuntu:22.04", "glibc", &[2, 35]),
    ("ubuntu:jammy", "glibc", &[2, 35]),
    ("ubuntu:24.04", "glibc", &[2, 39]),
    ("ubuntu:noble", "glibc", &[2, 39]),
    // Alpine (musl)
    ("alpine:3.16", "musl", &[1, 2, 3]),
    ("alpine:3.17", "musl", &[1, 2, 3]),
    ("alpine:3.18", "musl", &[1, 2, 4]),
    ("alpine:3.19", "musl", &[1, 2, 4]),
    ("alpine:3.20", "musl", &[1, 2, 5]),
    // AlmaLinux / Rocky / RHEL
    ("almalinux:8", "glibc", &[2, 28]),
    ("almalinux:9", "glibc", &[2, 34]),
    ("rockylinux:8", "glibc", &[2, 28]),
    ("rockylinux:9", "glibc", &[2, 34]),
    ("redhat/ubi8", "glibc", &[2, 28]),
    ("redhat/ubi9", "glibc", &[2, 34]),
    // Fedora
    ("fedora:39", "glibc", &[2, 38]),
    ("fedora:40", "glibc", &[2, 39]),
    ("fedora:41", "glibc", &[2, 40]),
    ("fedora:42", "glibc", &[2, 41]),
];

// GHA runner image → libc. Runners are Ubuntu-based; Windows/macOS return None.
const RUNNER_LIBC: &[(&str, &str, &[u32])] = &[
    ("ubuntu-20.04", "glibc", &[2, 31]),
    ("ubuntu-22.04", "glibc", &[2, 35]),
    ("ubuntu-24.04", "glibc", &[2, 39]),
    // `ubuntu-latest` rolls forward; today it points at 24.04. Using the newer
    // floor under-flags compat issues (wheel that works on 24.04 may not on 22.04).
    ("ubuntu-latest", "glibc", &[2, 39]),
];

fn distro_map() -> &'static HashMap<&'static str, LibcVersion> {
    static MAP: OnceLock<HashMap<&'static str, LibcVersion>> = OnceLock::new();
    MAP.get_or_init(|| {
        DISTRO_LIBC
            .iter()
            .map(|(k, fam, ver)| (*k, LibcVersion::new(fam, ver)))
            .collect()
    })
}

fn runner_map() -> &'static HashMap<&'static str, LibcVersion> {
    static MAP: OnceLock<HashMap<&'static str, LibcVersion>> = OnceLock::new();
    MAP.get_or_init(|| {
        RUNNER_LIBC
            .iter()
            .map(|(k, fam, ver)| (*k, LibcVersion::new(fam, ver)))
            .collect()
    })
}

/// Look up a libc version for a distro reference like `debian:bookworm`
/// (`lookup_distro_libc`). Returns `None` when unknown. Tolerates the Python-
/// image shape `python:<py-ver>-<distro-codename>` by splitting on `-`/`:` and
/// recognising a trailing distro codename (`python:3.12-bookworm`,
/// `python:3.13-alpine3.19`).
pub fn lookup_distro_libc(distro_ref: &str) -> Option<LibcVersion> {
    let map = distro_map();
    if let Some(v) = map.get(distro_ref) {
        return Some(v.clone());
    }
    // Split on "-" / ":" and check each suffix segment against the codename map.
    for part in distro_ref.replace(':', "-").split('-') {
        // `alpine3.19` form → `alpine:3.19`.
        if let Some(ver) = part.strip_prefix("alpine") {
            if !ver.is_empty() {
                let key = format!("alpine:{ver}");
                if let Some(v) = map.get(key.as_str()) {
                    return Some(v.clone());
                }
            }
        }
        // Codename-only Debian/Ubuntu variants: bookworm, bullseye, …
        for distro in ["debian", "ubuntu"] {
            let key = format!("{distro}:{part}");
            if let Some(v) = map.get(key.as_str()) {
                return Some(v.clone());
            }
        }
    }
    None
}

/// Look up libc for a GHA `runs-on:` value (`lookup_runner_libc`). Returns
/// `None` for Windows/macOS runners (no libc applicable).
pub fn lookup_runner_libc(runner_ref: &str) -> Option<LibcVersion> {
    runner_map().get(runner_ref).cloned()
}

/// Read-only view of the distro table in declaration order (`known_distros`).
pub fn known_distros() -> Vec<(&'static str, LibcVersion)> {
    DISTRO_LIBC
        .iter()
        .map(|(k, fam, ver)| (*k, LibcVersion::new(fam, ver)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> Option<String> {
        lookup_distro_libc(x).map(|v| v.as_str())
    }

    #[test]
    fn direct_and_python_image_forms() {
        assert_eq!(s("debian:bookworm").as_deref(), Some("glibc 2.36"));
        assert_eq!(s("python:3.12-bookworm").as_deref(), Some("glibc 2.36"));
        assert_eq!(s("python:3.13-slim-bookworm").as_deref(), Some("glibc 2.36"));
        assert_eq!(s("python:3.13-alpine3.19").as_deref(), Some("musl 1.2.4"));
        assert_eq!(s("alpine:3.19").as_deref(), Some("musl 1.2.4"));
        assert_eq!(s("python:3.11-bullseye").as_deref(), Some("glibc 2.31"));
        assert_eq!(s("ubuntu:jammy").as_deref(), Some("glibc 2.35"));
        assert_eq!(s("fedora:41").as_deref(), Some("glibc 2.40"));
        assert_eq!(s("alpine3.20").as_deref(), Some("musl 1.2.5"));
        assert_eq!(s("python:3.10-alpine3.16").as_deref(), Some("musl 1.2.3"));
        // Key containing a slash resolves via direct lookup.
        assert_eq!(s("redhat/ubi9").as_deref(), Some("glibc 2.34"));
        // Dash-separated (non-colon) codename form.
        assert_eq!(s("debian-bookworm").as_deref(), Some("glibc 2.36"));
        assert_eq!(s("python:3.9-slim-buster").as_deref(), Some("glibc 2.28"));
    }

    #[test]
    fn unknown_returns_none() {
        assert_eq!(s("python:3.12-slim"), None);
        assert_eq!(s("unknown:thing"), None);
    }

    #[test]
    fn runner_lookup() {
        assert_eq!(lookup_runner_libc("ubuntu-22.04").map(|v| v.as_str()).as_deref(), Some("glibc 2.35"));
        assert_eq!(lookup_runner_libc("ubuntu-latest").map(|v| v.as_str()).as_deref(), Some("glibc 2.39"));
        assert_eq!(lookup_runner_libc("windows-latest"), None);
        assert_eq!(lookup_runner_libc("macos-14"), None);
    }

    #[test]
    fn known_distros_count_and_order() {
        let all = known_distros();
        assert_eq!(all.len(), 25);
        assert_eq!(all[0].0, "debian:buster");
        assert_eq!(all[2].0, "debian:bookworm");
        // Version tuples are lexically comparable across differing lengths.
        assert!(LibcVersion::new("glibc", &[2, 36]) < LibcVersion::new("glibc", &[2, 39]));
    }
}
