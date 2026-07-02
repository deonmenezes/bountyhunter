//! PEP 425 wheel filename parser + platform-tag decoder — Rust port of
//! `packages/sca/wheel_compat/wheel_tags.py`. Pure over the filename string.

use std::sync::OnceLock;

use mantishack_sca_platform_matrix::LibcVersion;
use regex::Regex;

/// Decoded platform tag from a wheel filename (`WheelTag`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WheelTag {
    pub arch: Option<String>,
    pub libc: Option<LibcVersion>,
    pub os: String,
    pub raw: String,
    pub macos_version: Option<(u32, u32)>,
}

/// Canonicalise the architecture portion of a platform tag
/// (`_PLATFORM_ARCH_ALIASES`). Unknown arches pass through; `universal2` → `any`.
fn platform_arch_alias(arch: &str) -> &str {
    match arch {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        "armv7l" => "armv7l",
        "i686" | "i386" => "i686",
        "ppc64le" => "ppc64le",
        "ppc64" => "ppc64",
        "s390x" => "s390x",
        "universal2" => "any",
        other => other,
    }
}

// manylinux legacy aliases → glibc (major, minor) per PEP 600.
fn manylinux_legacy(name: &str) -> Option<(u32, u32)> {
    match name {
        "manylinux1" => Some((2, 5)),
        "manylinux2010" => Some((2, 12)),
        "manylinux2014" => Some((2, 17)),
        _ => None,
    }
}

fn manylinux_new_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^manylinux_(\d+)_(\d+)_(.+)$").unwrap())
}
fn musllinux_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^musllinux_(\d+)_(\d+)_(.+)$").unwrap())
}
fn macosx_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^macosx_(\d+)_(\d+)_(.+)$").unwrap())
}
fn win_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(win_amd64|win32)$").unwrap())
}
fn linux_bare_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^linux_(.+)$").unwrap())
}
fn manylinux_legacy_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(manylinux1|manylinux2010|manylinux2014)_(.+)$").unwrap())
}

/// Parse one platform-tag component (no `.`-separated joins)
/// (`_parse_single_platform_tag`).
pub fn parse_single_platform_tag(tag: &str) -> WheelTag {
    if tag == "any" {
        return WheelTag { arch: Some("any".into()), libc: None, os: "any".into(), raw: tag.into(), macos_version: None };
    }
    // manylinux_X_Y_<arch> (checked before the legacy aliases).
    if let Some(c) = manylinux_new_re().captures(tag) {
        let major: u32 = c[1].parse().unwrap();
        let minor: u32 = c[2].parse().unwrap();
        let arch = &c[3];
        return WheelTag {
            arch: Some(platform_arch_alias(arch).into()),
            libc: Some(LibcVersion::new("glibc", &[major, minor])),
            os: "linux".into(),
            raw: tag.into(),
            macos_version: None,
        };
    }
    // manylinux2014_<arch> etc.
    if let Some(c) = manylinux_legacy_re().captures(tag) {
        let name = &c[1];
        let arch = &c[2];
        let (maj, min) = manylinux_legacy(name).unwrap();
        return WheelTag {
            arch: Some(platform_arch_alias(arch).into()),
            libc: Some(LibcVersion::new("glibc", &[maj, min])),
            os: "linux".into(),
            raw: tag.into(),
            macos_version: None,
        };
    }
    // musllinux_X_Y_<arch>
    if let Some(c) = musllinux_re().captures(tag) {
        let major: u32 = c[1].parse().unwrap();
        let minor: u32 = c[2].parse().unwrap();
        let arch = &c[3];
        return WheelTag {
            arch: Some(platform_arch_alias(arch).into()),
            libc: Some(LibcVersion::new("musl", &[major, minor])),
            os: "linux".into(),
            raw: tag.into(),
            macos_version: None,
        };
    }
    // macosx_X_Y_<arch>
    if let Some(c) = macosx_re().captures(tag) {
        let major: u32 = c[1].parse().unwrap();
        let minor: u32 = c[2].parse().unwrap();
        let arch = &c[3];
        return WheelTag {
            arch: Some(platform_arch_alias(arch).into()),
            libc: None,
            os: "macosx".into(),
            raw: tag.into(),
            macos_version: Some((major, minor)),
        };
    }
    // Windows
    if win_re().is_match(tag) {
        let arch = if tag == "win_amd64" { "x86_64" } else { "i686" };
        return WheelTag { arch: Some(arch.into()), libc: None, os: "windows".into(), raw: tag.into(), macos_version: None };
    }
    // linux_<arch> — raw linux tag, no libc constraint declared.
    if let Some(c) = linux_bare_re().captures(tag) {
        let arch = &c[1];
        return WheelTag {
            arch: Some(platform_arch_alias(arch).into()),
            libc: None,
            os: "linux".into(),
            raw: tag.into(),
            macos_version: None,
        };
    }
    // Unknown platform tag — pass through with no constraints.
    WheelTag { arch: None, libc: None, os: "unknown".into(), raw: tag.into(), macos_version: None }
}

/// Parse a wheel filename and return one `WheelTag` per `.`-joined platform
/// component (`parse_wheel_filename`). `[]` when it isn't a PEP 425 wheel shape.
pub fn parse_wheel_filename(filename: &str) -> Vec<WheelTag> {
    let Some(stem) = filename.strip_suffix(".whl") else { return Vec::new() };
    let parts: Vec<&str> = stem.split('-').collect();
    // PEP 425: 5 parts (no build-tag) or 6 (with build-tag).
    if parts.len() < 5 {
        return Vec::new();
    }
    let platform_tag_joined = parts[parts.len() - 1];
    platform_tag_joined.split('.').map(parse_single_platform_tag).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(tag: &str) -> (Option<String>, Option<String>, String, Option<(u32, u32)>) {
        let w = parse_single_platform_tag(tag);
        (w.arch, w.libc.map(|l| l.as_str()), w.os, w.macos_version)
    }

    #[test]
    fn platform_tags() {
        assert_eq!(t("any"), (Some("any".into()), None, "any".into(), None));
        assert_eq!(t("manylinux_2_38_aarch64"), (Some("aarch64".into()), Some("glibc 2.38".into()), "linux".into(), None));
        assert_eq!(t("manylinux2014_x86_64"), (Some("x86_64".into()), Some("glibc 2.17".into()), "linux".into(), None));
        assert_eq!(t("manylinux2010_i686"), (Some("i686".into()), Some("glibc 2.12".into()), "linux".into(), None));
        assert_eq!(t("manylinux1_x86_64"), (Some("x86_64".into()), Some("glibc 2.5".into()), "linux".into(), None));
        assert_eq!(t("musllinux_1_2_x86_64"), (Some("x86_64".into()), Some("musl 1.2".into()), "linux".into(), None));
        assert_eq!(t("macosx_11_0_arm64"), (Some("aarch64".into()), None, "macosx".into(), Some((11, 0))));
        assert_eq!(t("macosx_10_9_universal2"), (Some("any".into()), None, "macosx".into(), Some((10, 9))));
        assert_eq!(t("win_amd64"), (Some("x86_64".into()), None, "windows".into(), None));
        assert_eq!(t("win32"), (Some("i686".into()), None, "windows".into(), None));
        assert_eq!(t("linux_armv7l"), (Some("armv7l".into()), None, "linux".into(), None));
        assert_eq!(t("manylinux_2_17_ppc64le"), (Some("ppc64le".into()), Some("glibc 2.17".into()), "linux".into(), None));
        assert_eq!(t("frobnicate_1_2"), (None, None, "unknown".into(), None));
        assert_eq!(t("linux_x86_64"), (Some("x86_64".into()), None, "linux".into(), None));
    }

    #[test]
    fn filenames() {
        let w = parse_wheel_filename("z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl");
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].raw, "manylinux_2_38_aarch64");
        assert_eq!(w[0].libc.as_ref().unwrap().as_str(), "glibc 2.38");

        assert_eq!(parse_wheel_filename("pkg-1.0-py3-none-any.whl")[0].os, "any");

        // Build-tag (6 parts) + universal macos double platform tag.
        let w = parse_wheel_filename("pkg-1.0-1-cp311-cp311-macosx_11_0_arm64.macosx_11_0_x86_64.whl");
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].arch.as_deref(), Some("aarch64"));
        assert_eq!(w[1].arch.as_deref(), Some("x86_64"));

        assert!(parse_wheel_filename("notawheel.txt").is_empty());
        assert!(parse_wheel_filename("tooshort-1.0-any.whl").is_empty());
        assert_eq!(parse_wheel_filename("pkg-1.0-cp39-abi3-win_amd64.whl")[0].os, "windows");
    }
}
