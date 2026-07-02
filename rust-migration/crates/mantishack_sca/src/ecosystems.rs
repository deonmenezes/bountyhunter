//! Canonical ecosystem names — Rust port of `packages/sca/ecosystems.py`.
//!
//! OSV is case-sensitive (`PyPI` works, `pypi` 400s), so user-supplied
//! ecosystem strings must be canonicalised before any registry / OSV call.

/// The known ecosystems accepted by `mantishack-sca` (and by OSV), in
/// declaration order (`KNOWN_ECOSYSTEMS`).
pub const KNOWN_ECOSYSTEMS: &[&str] = &[
    "PyPI",
    "npm",
    "Maven",
    "Cargo",
    "Go",
    "RubyGems",
    "NuGet",
    "Packagist",
    "vcpkg",
    "ConanCenter",
    "OSS-Fuzz",
    "GitHub Actions",
];

/// Return the canonical ecosystem name, or `None` if unrecognised
/// (`canonicalise`). Case-insensitive.
pub fn canonicalise(ecosystem: &str) -> Option<&'static str> {
    let lower = ecosystem.to_lowercase();
    KNOWN_ECOSYSTEMS.iter().copied().find(|e| e.to_lowercase() == lower)
}

/// Comma-separated, lexically sorted list of known ecosystems for error
/// messages (`known_list`).
pub fn known_list() -> String {
    let mut names: Vec<&str> = KNOWN_ECOSYSTEMS.to_vec();
    names.sort_unstable();
    names.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalise_cases() {
        assert_eq!(canonicalise("pypi"), Some("PyPI"));
        assert_eq!(canonicalise("PyPI"), Some("PyPI"));
        assert_eq!(canonicalise("github actions"), Some("GitHub Actions"));
        assert_eq!(canonicalise("NPM"), Some("npm"));
        assert_eq!(canonicalise("bogus"), None);
    }

    #[test]
    fn known_list_sorted() {
        assert_eq!(
            known_list(),
            "Cargo, ConanCenter, GitHub Actions, Go, Maven, NuGet, OSS-Fuzz, Packagist, PyPI, RubyGems, npm, vcpkg"
        );
    }
}
