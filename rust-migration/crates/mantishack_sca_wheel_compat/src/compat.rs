//! Wheel-matrix builder + compat cross-check engine — Rust port of the pure
//! parts of `packages/sca/wheel_compat/compat.py`.
//!
//! `build_wheel_matrix` / `best_match` / `verdict_for_pair` / `check_compat`
//! plus the `_is_stable_version` / `_version_key` helpers port here. The PyPI
//! `get_metadata` fetch inside `wheel_matrix_for_version` and the cached
//! `find_compatible_version` release-history walk stay call-site in Python and
//! drive `build_wheel_matrix` + `check_compat` with already-fetched data.

use std::sync::OnceLock;

use mantishack_sca_platform_matrix::{PlatformPair, ProjectPlatformMatrix};
use regex::Regex;

use crate::wheel_tags::{parse_wheel_filename, WheelTag};

/// One compat decision for a (project pair, package version) (`CompatVerdict`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompatVerdict {
    pub pair: PlatformPair,
    pub verdict: String,
    pub reason: String,
    pub matching_wheel: Option<String>,
}

/// The platform constraints a `(pkg, version)` ships wheels for, plus the
/// sdist-availability flag (`WheelMatrix`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WheelMatrix {
    pub name: String,
    pub version: String,
    pub wheel_tags: Vec<WheelTag>,
    pub has_sdist: bool,
}

impl WheelMatrix {
    /// Python `__bool__`: truthy when there is any wheel tag or an sdist.
    pub fn is_truthy(&self) -> bool {
        !self.wheel_tags.is_empty() || self.has_sdist
    }
}

/// Build the wheel matrix from a version's already-fetched release filenames
/// (the pure core of `wheel_matrix_for_version`). Files ending `.tar.gz`/`.zip`
/// set `has_sdist`; `.whl` files contribute parsed platform tags.
pub fn build_wheel_matrix(name: &str, version: &str, filenames: &[String]) -> WheelMatrix {
    let mut wheel_tags = Vec::new();
    let mut has_sdist = false;
    for filename in filenames {
        if filename.ends_with(".tar.gz") || filename.ends_with(".zip") {
            has_sdist = true;
            continue;
        }
        if filename.ends_with(".whl") {
            wheel_tags.extend(parse_wheel_filename(filename));
        }
    }
    WheelMatrix { name: name.to_string(), version: version.to_string(), wheel_tags, has_sdist }
}

/// For one (arch, libc) project pair, return the wheel-tag that best satisfies
/// it, or `None` (`_best_match`). Returns the FIRST matching tag in file order.
pub fn best_match<'a>(pair: &PlatformPair, wheel_tags: &'a [WheelTag]) -> Option<&'a WheelTag> {
    for w in wheel_tags {
        if w.arch.as_deref() == Some("any") && w.os == "any" {
            return Some(w);
        }
        if w.arch.as_deref() != Some(pair.arch.as_str()) {
            continue;
        }
        if pair.libc.is_none() {
            // Non-Linux project pair — wheel must match the OS.
            if w.os == "windows" {
                return Some(w);
            }
            if w.os == "macosx" {
                if let (Some(pv), Some(wv)) = (pair.macos_version, w.macos_version) {
                    if wv > pv {
                        continue; // wheel requires a newer macOS than accepted
                    }
                }
                return Some(w);
            }
            continue;
        }
        // Linux pair → wheel must be Linux + libc family + version OK.
        if w.os != "linux" {
            continue;
        }
        let Some(wlibc) = &w.libc else {
            return Some(w); // raw linux_<arch> tag: no libc constraint
        };
        let plibc = pair.libc.as_ref().unwrap();
        if wlibc.family != plibc.family {
            continue;
        }
        if wlibc.version > plibc.version {
            continue; // wheel requires newer libc than provided
        }
        return Some(w);
    }
    None
}

/// Decide the compat verdict for one project pair against one wheel matrix
/// (`_verdict_for_pair`).
pub fn verdict_for_pair(pair: &PlatformPair, wm: &WheelMatrix) -> CompatVerdict {
    let ps = pair.as_str();
    if wm.wheel_tags.is_empty() && wm.has_sdist {
        return CompatVerdict {
            pair: pair.clone(),
            verdict: "sdist_only".into(),
            reason: format!(
                "{}=={} ships no wheels; install requires a build environment (compilers, headers) on {}",
                wm.name, wm.version, ps
            ),
            matching_wheel: None,
        };
    }
    if wm.wheel_tags.is_empty() && !wm.has_sdist {
        return CompatVerdict {
            pair: pair.clone(),
            verdict: "uninstallable".into(),
            reason: format!("{}=={} has no wheels and no sdist on PyPI for {}", wm.name, wm.version, ps),
            matching_wheel: None,
        };
    }

    if let Some(m) = best_match(pair, &wm.wheel_tags) {
        return CompatVerdict {
            pair: pair.clone(),
            verdict: "ok".into(),
            reason: "installable wheel found".into(),
            matching_wheel: Some(m.raw.clone()),
        };
    }

    let same_arch: Vec<&WheelTag> = wm
        .wheel_tags
        .iter()
        .filter(|w| w.arch.as_deref() == Some(pair.arch.as_str()))
        .collect();
    if same_arch.is_empty() {
        if wm.has_sdist {
            return CompatVerdict {
                pair: pair.clone(),
                verdict: "sdist_only".into(),
                reason: format!(
                    "{}=={} has wheels for other arches but none for {}; install on {} requires sdist build",
                    wm.name, wm.version, pair.arch, ps
                ),
                matching_wheel: None,
            };
        }
        return CompatVerdict {
            pair: pair.clone(),
            verdict: "arch_gap".into(),
            reason: format!(
                "{}=={} has no wheels for {} and no sdist; not installable on {}",
                wm.name, wm.version, pair.arch, ps
            ),
            matching_wheel: None,
        };
    }

    // Same-arch wheels exist; closest mismatch is libc.
    if let Some(plibc) = &pair.libc {
        let same_family: Vec<&WheelTag> = same_arch
            .iter()
            .copied()
            .filter(|w| w.libc.as_ref().map_or(false, |l| l.family == plibc.family))
            .collect();
        if !same_family.is_empty() {
            let min_libc = same_family
                .iter()
                .copied()
                .min_by(|a, b| a.libc.as_ref().unwrap().version.cmp(&b.libc.as_ref().unwrap().version))
                .unwrap();
            return CompatVerdict {
                pair: pair.clone(),
                verdict: "libc_too_new".into(),
                reason: format!(
                    "{}=={}'s {} wheels require {} or newer; project pair has only {}",
                    wm.name, wm.version, pair.arch, min_libc.libc.as_ref().unwrap().as_str(), plibc.as_str()
                ),
                matching_wheel: Some(min_libc.raw.clone()),
            };
        }
    }

    // macOS version gating, mirroring the libc_too_new path.
    if let Some(pmac) = pair.macos_version {
        let same_macos: Vec<&WheelTag> = same_arch
            .iter()
            .copied()
            .filter(|w| w.os == "macosx" && w.macos_version.is_some())
            .collect();
        if !same_macos.is_empty() {
            let min_required = same_macos.iter().copied().min_by_key(|w| w.macos_version.unwrap()).unwrap();
            let mreq = min_required.macos_version.unwrap();
            if mreq > pmac {
                return CompatVerdict {
                    pair: pair.clone(),
                    verdict: "macos_too_new".into(),
                    reason: format!(
                        "{}=={}'s {} wheels require macOS {}.{} or newer; project pair targets macOS {}.{}",
                        wm.name, wm.version, pair.arch, mreq.0, mreq.1, pmac.0, pmac.1
                    ),
                    matching_wheel: Some(min_required.raw.clone()),
                };
            }
        }
    }

    // Fallback — no libc info or different family; surface generic.
    if wm.has_sdist {
        let is_alpine_glibc_only = pair.libc.as_ref().map_or(false, |l| l.family == "musl")
            && same_arch.iter().any(|w| w.libc.as_ref().map_or(false, |l| l.family == "glibc"));
        let reason = if is_alpine_glibc_only {
            format!(
                "{}=={} ships manylinux (glibc) wheels for {} but no musllinux wheel for {}. sdist available; on Alpine add ``apk add build-base python3-dev`` to your Dockerfile to enable source build, or switch base to a glibc image (``python:3.X-bookworm``).",
                wm.name, wm.version, pair.arch, ps
            )
        } else {
            format!(
                "{}=={}'s {} wheels don't match {}; sdist available but requires build environment",
                wm.name, wm.version, pair.arch, ps
            )
        };
        return CompatVerdict { pair: pair.clone(), verdict: "sdist_only".into(), reason, matching_wheel: None };
    }
    CompatVerdict {
        pair: pair.clone(),
        verdict: "arch_gap".into(),
        reason: format!("{}=={} has no wheel compatible with {}", wm.name, wm.version, ps),
        matching_wheel: None,
    }
}

/// For every project pair, decide the compat verdict (`check_compat`). Iterates
/// the matrix's pair set (order is set-defined, as in Python).
pub fn check_compat(matrix: &ProjectPlatformMatrix, wm: &WheelMatrix) -> Vec<CompatVerdict> {
    matrix.iter().map(|pair| verdict_for_pair(pair, wm)).collect()
}

fn stable_version_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$").unwrap())
}

/// True when `v` is a stable-semver-ish version (`_is_stable_version`).
pub fn is_stable_version(v: &str) -> bool {
    stable_version_re().is_match(v)
}

/// Numeric-component sort key, missing components as 0 (`_version_key`).
/// Non-matching versions yield `[0]`.
pub fn version_key(v: &str) -> Vec<u32> {
    match stable_version_re().captures(v) {
        Some(c) => (1..=4)
            .map(|i| c.get(i).map(|m| m.as_str().parse().unwrap_or(0)).unwrap_or(0))
            .collect(),
        None => vec![0],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantishack_sca_platform_matrix::LibcVersion;

    fn pair(arch: &str, libc: Option<(&str, &[u32])>, macos: Option<(u32, u32)>) -> PlatformPair {
        let mut p = PlatformPair::new(arch, libc.map(|(f, v)| LibcVersion::new(f, v)), "s".into());
        p.macos_version = macos;
        p
    }
    fn files(fs: &[&str]) -> Vec<String> {
        fs.iter().map(|s| s.to_string()).collect()
    }
    fn v(p: &PlatformPair, name: &str, ver: &str, fs: &[&str]) -> CompatVerdict {
        verdict_for_pair(p, &build_wheel_matrix(name, ver, &files(fs)))
    }

    #[test]
    fn ok_verdicts() {
        let g236 = pair("x86_64", Some(("glibc", &[2, 36])), None);
        let r = v(&g236, "pkg", "1.0", &["pkg-1.0-py3-none-any.whl"]);
        assert_eq!(r.verdict, "ok");
        assert_eq!(r.matching_wheel.as_deref(), Some("any"));
        let r = v(&g236, "z3", "4.0", &["z3-4.0-py3-none-manylinux_2_17_x86_64.whl"]);
        assert_eq!((r.verdict.as_str(), r.matching_wheel.as_deref()), ("ok", Some("manylinux_2_17_x86_64")));
    }

    #[test]
    fn libc_too_new_verdict() {
        let g217 = pair("x86_64", Some(("glibc", &[2, 17])), None);
        let r = v(&g217, "z3", "4.16", &["z3-4.16-py3-none-manylinux_2_38_x86_64.whl"]);
        assert_eq!(r.verdict, "libc_too_new");
        assert_eq!(r.reason, "z3==4.16's x86_64 wheels require glibc 2.38 or newer; project pair has only glibc 2.17");
        assert_eq!(r.matching_wheel.as_deref(), Some("manylinux_2_38_x86_64"));
    }

    #[test]
    fn sdist_and_uninstallable() {
        let g = pair("x86_64", Some(("glibc", &[2, 36])), None);
        let r = v(&g, "pkg", "1.0", &["pkg-1.0.tar.gz"]);
        assert_eq!(r.verdict, "sdist_only");
        assert_eq!(r.reason, "pkg==1.0 ships no wheels; install requires a build environment (compilers, headers) on x86_64/glibc 2.36");
        let r = v(&g, "pkg", "1.0", &["pkg-1.0.md"]);
        assert_eq!(r.verdict, "uninstallable");
        assert_eq!(r.reason, "pkg==1.0 has no wheels and no sdist on PyPI for x86_64/glibc 2.36");
    }

    #[test]
    fn arch_gap_and_other_arch_sdist() {
        let a = pair("aarch64", Some(("glibc", &[2, 36])), None);
        let r = v(&a, "pkg", "1.0", &["pkg-1.0-py3-none-manylinux_2_17_x86_64.whl"]);
        assert_eq!(r.verdict, "arch_gap");
        assert_eq!(r.reason, "pkg==1.0 has no wheels for aarch64 and no sdist; not installable on aarch64/glibc 2.36");
        let r = v(&a, "pkg", "1.0", &["pkg-1.0-py3-none-manylinux_2_17_x86_64.whl", "pkg-1.0.tar.gz"]);
        assert_eq!(r.verdict, "sdist_only");
        assert_eq!(r.reason, "pkg==1.0 has wheels for other arches but none for aarch64; install on aarch64/glibc 2.36 requires sdist build");
    }

    #[test]
    fn alpine_glibc_only() {
        let musl = pair("x86_64", Some(("musl", &[1, 2, 3])), None);
        let r = v(&musl, "pkg", "1.0", &["pkg-1.0-py3-none-manylinux_2_17_x86_64.whl", "pkg-1.0.tar.gz"]);
        assert_eq!(r.verdict, "sdist_only");
        assert_eq!(r.reason, "pkg==1.0 ships manylinux (glibc) wheels for x86_64 but no musllinux wheel for x86_64/musl 1.2.3. sdist available; on Alpine add ``apk add build-base python3-dev`` to your Dockerfile to enable source build, or switch base to a glibc image (``python:3.X-bookworm``).");
    }

    #[test]
    fn macos_gating() {
        let mac13 = pair("aarch64", None, Some((13, 0)));
        let r = v(&mac13, "pkg", "1.0", &["pkg-1.0-cp39-cp39-macosx_14_0_arm64.whl"]);
        assert_eq!(r.verdict, "macos_too_new");
        assert_eq!(r.reason, "pkg==1.0's aarch64 wheels require macOS 14.0 or newer; project pair targets macOS 13.0");
        assert_eq!(r.matching_wheel.as_deref(), Some("macosx_14_0_arm64"));
        let r = v(&mac13, "pkg", "1.0", &["pkg-1.0-cp39-cp39-macosx_12_0_arm64.whl"]);
        assert_eq!((r.verdict.as_str(), r.matching_wheel.as_deref()), ("ok", Some("macosx_12_0_arm64")));
    }

    #[test]
    fn windows_ok() {
        let w = pair("x86_64", None, None);
        let r = v(&w, "pkg", "1.0", &["pkg-1.0-cp39-cp39-win_amd64.whl"]);
        assert_eq!((r.verdict.as_str(), r.matching_wheel.as_deref()), ("ok", Some("win_amd64")));
    }

    #[test]
    fn best_match_semantics() {
        let g = pair("x86_64", Some(("glibc", &[2, 36])), None);
        let tags: Vec<WheelTag> = ["a-1-py3-none-manylinux_2_17_x86_64.whl", "b-1-py3-none-manylinux_2_30_x86_64.whl"]
            .iter().flat_map(|f| parse_wheel_filename(f)).collect();
        assert_eq!(best_match(&g, &tags).unwrap().raw, "manylinux_2_17_x86_64");
        let bare = parse_wheel_filename("a-1-py3-none-linux_x86_64.whl");
        assert_eq!(best_match(&g, &bare).unwrap().raw, "linux_x86_64");
        let musl = pair("x86_64", Some(("musl", &[1, 2, 3])), None);
        let mt = parse_wheel_filename("a-1-py3-none-musllinux_1_2_x86_64.whl");
        assert_eq!(best_match(&musl, &mt).unwrap().raw, "musllinux_1_2_x86_64");
    }

    #[test]
    fn check_compat_multi() {
        let mut m = ProjectPlatformMatrix::new();
        let g217 = pair("x86_64", Some(("glibc", &[2, 17])), None);
        let a = pair("aarch64", Some(("glibc", &[2, 36])), None);
        m.add(g217);
        m.add(a);
        let wm = build_wheel_matrix("z3", "4.16", &files(&["z3-4.16-py3-none-manylinux_2_38_x86_64.whl"]));
        let verdicts: std::collections::HashMap<String, String> =
            check_compat(&m, &wm).into_iter().map(|c| (c.pair.as_str(), c.verdict)).collect();
        assert_eq!(verdicts["x86_64/glibc 2.17"], "libc_too_new");
        assert_eq!(verdicts["aarch64/glibc 2.36"], "arch_gap");
    }

    #[test]
    fn version_helpers() {
        for (v, want) in [("1.2.3", true), ("v1.2", true), ("1.0.0.1", true), ("1.0b1", false),
            ("1.0.dev0", false), ("2024.1", true), ("1.0+local", false), ("1", true)] {
            assert_eq!(is_stable_version(v), want, "{v}");
        }
        assert_eq!(version_key("1.2.3"), vec![1, 2, 3, 0]);
        assert_eq!(version_key("v2.0"), vec![2, 0, 0, 0]);
        assert_eq!(version_key("1"), vec![1, 0, 0, 0]);
        assert_eq!(version_key("1.0.0.5"), vec![1, 0, 0, 5]);
        assert_eq!(version_key("garbage"), vec![0]);
    }
}
