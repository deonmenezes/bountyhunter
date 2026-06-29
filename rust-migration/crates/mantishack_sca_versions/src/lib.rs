/// Per-ecosystem version comparators — Rust port of packages/sca/versions/.
///
/// Public API (mirrors Python __init__.py):
///   compare(ecosystem, a, b) -> Result<i32, VersionError>
///   in_range(ecosystem, version, events) -> Result<bool, VersionError>
///
/// Events are OSV-style: [{introduced/fixed/last_affected/limit: version_str}]

pub mod semver;
pub mod pep440;
pub mod maven;
pub mod debian;
pub mod nuget;
pub mod gem;
pub mod composer;

use std::collections::HashMap;

/// Mirrors Python's VersionError (ValueError subclass).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionError(pub String);

impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for VersionError {}

fn canonical_ecosystem(eco: &str) -> &'static str {
    match eco.to_lowercase().as_str() {
        "pypi" | "python" => "PyPI",
        "npm" | "javascript" | "node" => "npm",
        "maven" | "java" | "gradle" => "Maven",
        "go" | "golang" => "Go",
        "cargo" | "crates.io" | "rust" => "Cargo",
        "rubygems" | "ruby" | "gem" => "RubyGems",
        "nuget" | "csharp" | "dotnet" => "NuGet",
        "packagist" | "composer" | "php" => "Packagist",
        "debian" | "apt" | "deb" => "Debian",
        _ => "",
    }
}

fn dispatch(ecosystem: &str, a: &str, b: &str) -> Result<i32, VersionError> {
    let eco = canonical_ecosystem(ecosystem);
    match eco {
        "npm" | "Cargo" | "Go" => semver::compare(a, b).map_err(|e| VersionError(e)),
        "PyPI" => pep440::compare(a, b).map_err(|e| VersionError(e)),
        "Maven" => maven::compare(a, b).map_err(|e| VersionError(e)),
        "RubyGems" => gem::compare(a, b).map_err(|e| VersionError(e)),
        "NuGet" => nuget::compare(a, b).map_err(|e| VersionError(e)),
        "Packagist" => composer::compare(a, b).map_err(|e| VersionError(e)),
        "Debian" => debian::compare(a, b).map_err(|e| VersionError(e)),
        "" => Err(VersionError(format!("no version comparator for ecosystem: {}", ecosystem))),
        unknown => Err(VersionError(format!("no version comparator for ecosystem: {}", unknown))),
    }
}

/// Return -1, 0, or 1 for a < b, a == b, a > b within the ecosystem's ordering.
pub fn compare(ecosystem: &str, a: &str, b: &str) -> Result<i32, VersionError> {
    dispatch(ecosystem, a, b)
}

/// OSV-style event map: one of {introduced, fixed, last_affected, limit} -> version_str.
pub type Event = HashMap<String, String>;

/// True if `version` falls within any vulnerable interval defined by `events`.
pub fn in_range(ecosystem: &str, version: &str, events: &[Event]) -> Result<bool, VersionError> {
    if events.is_empty() {
        return Ok(false);
    }

    // Build intervals: (lower, lower_inclusive, upper Option<String>, upper_inclusive)
    let mut intervals: Vec<(String, bool, Option<String>, bool)> = Vec::new();
    let mut current_lower = "0".to_string();
    let mut current_lower_inclusive = true;
    let mut has_open_lower = false;

    for ev in events {
        if let Some(v) = ev.get("introduced") {
            current_lower = v.clone();
            current_lower_inclusive = true;
            has_open_lower = true;
        } else if let Some(v) = ev.get("fixed") {
            intervals.push((current_lower.clone(), current_lower_inclusive, Some(v.clone()), false));
            current_lower = "0".to_string();
            has_open_lower = false;
        } else if let Some(v) = ev.get("last_affected") {
            intervals.push((current_lower.clone(), current_lower_inclusive, Some(v.clone()), true));
            current_lower = "0".to_string();
            has_open_lower = false;
        } else if let Some(v) = ev.get("limit") {
            intervals.push((current_lower.clone(), current_lower_inclusive, Some(v.clone()), false));
            current_lower = "0".to_string();
            has_open_lower = false;
        }
    }
    if has_open_lower {
        intervals.push((current_lower, current_lower_inclusive, None, false));
    }

    for (lo, lo_incl, hi, hi_incl) in &intervals {
        if within(ecosystem, version, lo, *lo_incl, hi.as_deref(), *hi_incl)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn within(
    ecosystem: &str,
    version: &str,
    lo: &str,
    lo_incl: bool,
    hi: Option<&str>,
    hi_incl: bool,
) -> Result<bool, VersionError> {
    if lo != "0" {
        let c_lo = compare(ecosystem, version, lo)?;
        if lo_incl {
            if c_lo < 0 { return Ok(false); }
        } else {
            if c_lo <= 0 { return Ok(false); }
        }
    }
    if let Some(hi_str) = hi {
        let c_hi = compare(ecosystem, version, hi_str)?;
        if hi_incl {
            return Ok(c_hi <= 0);
        } else {
            return Ok(c_hi < 0);
        }
    }
    Ok(true) // open upper bound
}

// ---------------------------------------------------------------------------
// PyO3 bindings
// ---------------------------------------------------------------------------

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pyfunction]
fn py_compare(ecosystem: &str, a: &str, b: &str) -> PyResult<i32> {
    compare(ecosystem, a, b).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.0))
}

#[cfg(feature = "python")]
#[pyfunction]
fn py_in_range(
    ecosystem: &str,
    version: &str,
    events: Vec<HashMap<String, String>>,
) -> PyResult<bool> {
    in_range(ecosystem, version, &events)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.0))
}

#[cfg(feature = "python")]
#[pymodule]
fn mantishack_sca_versions(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_compare, m)?)?;
    m.add_function(wrap_pyfunction!(py_in_range, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Parity oracle tests — golden vectors produced by running the Python source
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ev(key: &str, val: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(key.to_string(), val.to_string());
        m
    }

    // ====== SEMVER (npm, Cargo, Go) — 15 golden cases ======

    #[test] fn semver_lt() { assert_eq!(compare("npm", "1.2.3", "1.2.4").unwrap(), -1); }
    #[test] fn semver_gt() { assert_eq!(compare("npm", "1.2.4", "1.2.3").unwrap(), 1); }
    #[test] fn semver_eq() { assert_eq!(compare("npm", "1.2.3", "1.2.3").unwrap(), 0); }
    #[test] fn semver_pre_lt_release() { assert_eq!(compare("npm", "1.0.0-alpha", "1.0.0").unwrap(), -1); }
    #[test] fn semver_release_gt_pre() { assert_eq!(compare("npm", "1.0.0", "1.0.0-alpha").unwrap(), 1); }
    #[test] fn semver_alpha_lt_beta() { assert_eq!(compare("npm", "1.0.0-alpha", "1.0.0-beta").unwrap(), -1); }
    #[test] fn semver_numeric_pre() { assert_eq!(compare("npm", "1.0.0-1", "1.0.0-2").unwrap(), -1); }
    #[test] fn semver_pre_longer_wins() { assert_eq!(compare("npm", "1.0.0-alpha.1", "1.0.0-alpha").unwrap(), 1); }
    #[test] fn semver_go_v_prefix() { assert_eq!(compare("Go", "v1.2.3", "1.2.3").unwrap(), 0); }
    #[test] fn semver_go_short() { assert_eq!(compare("Go", "v1", "v1.0.0").unwrap(), 0); }
    #[test] fn semver_cargo_rc() { assert_eq!(compare("Cargo", "2.0.0-rc.1", "2.0.0-rc.2").unwrap(), -1); }
    #[test] fn semver_alpha_gt_numeric_pre() { assert_eq!(compare("npm", "1.0.0-alpha", "1.0.0-1").unwrap(), 1); }
    #[test] fn semver_beta_gt_alpha1() { assert_eq!(compare("npm", "1.0.0-beta", "1.0.0-alpha.1").unwrap(), 1); }
    #[test] fn semver_build_ignored() { assert_eq!(compare("npm", "1.0.0+build1", "1.0.0+build2").unwrap(), 0); }
    #[test] fn semver_pre_dot_cmp() { assert_eq!(compare("npm", "1.0.0-alpha.1", "1.0.0-alpha.2").unwrap(), -1); }

    // ====== PEP440 (PyPI) — 10 golden cases ======

    #[test] fn pep440_alpha_lt_release() { assert_eq!(compare("PyPI", "1.0a1", "1.0").unwrap(), -1); }
    #[test] fn pep440_beta_gt_alpha() { assert_eq!(compare("PyPI", "1.0b1", "1.0a2").unwrap(), 1); }
    #[test] fn pep440_rc_gt_beta() { assert_eq!(compare("PyPI", "1.0rc1", "1.0b3").unwrap(), 1); }
    #[test] fn pep440_post() { assert_eq!(compare("PyPI", "1.0", "1.0.post1").unwrap(), -1); }
    #[test] fn pep440_dev_lt_alpha() { assert_eq!(compare("PyPI", "1.0.dev1", "1.0a1").unwrap(), -1); }
    #[test] fn pep440_minor_lt() { assert_eq!(compare("PyPI", "1.1", "1.2").unwrap(), -1); }
    #[test] fn pep440_major_gt() { assert_eq!(compare("PyPI", "2.0", "1.9.9").unwrap(), 1); }
    #[test] fn pep440_eq() { assert_eq!(compare("PyPI", "1.0", "1.0").unwrap(), 0); }
    #[test] fn pep440_alpha_seq() { assert_eq!(compare("PyPI", "1.0a1", "1.0a2").unwrap(), -1); }
    #[test] fn pep440_post_seq() { assert_eq!(compare("PyPI", "1.0.post1", "1.0.post2").unwrap(), -1); }
    #[test] fn pep440_alias_python() { assert_eq!(compare("python", "1.0a1", "1.0").unwrap(), -1); }

    // ====== MAVEN — 13 golden cases ======

    #[test] fn maven_snapshot_lt_release() { assert_eq!(compare("Maven", "1.0-SNAPSHOT", "1.0").unwrap(), -1); }
    #[test] fn maven_alpha_lt_beta() { assert_eq!(compare("Maven", "1.0-alpha", "1.0-beta").unwrap(), -1); }
    #[test] fn maven_beta_lt_rc() { assert_eq!(compare("Maven", "1.0-beta", "1.0-rc").unwrap(), -1); }
    #[test] fn maven_rc_lt_release() { assert_eq!(compare("Maven", "1.0-rc", "1.0").unwrap(), -1); }
    #[test] fn maven_release_lt_sp() { assert_eq!(compare("Maven", "1.0", "1.0-sp1").unwrap(), -1); }
    #[test] fn maven_trailing_zero() { assert_eq!(compare("Maven", "1.0.0", "1.0").unwrap(), 0); }
    #[test] fn maven_ga_eq_release() { assert_eq!(compare("Maven", "1.0-ga", "1.0").unwrap(), 0); }
    #[test] fn maven_final_eq_release() { assert_eq!(compare("Maven", "1.0-final", "1.0").unwrap(), 0); }
    #[test] fn maven_numeric_gt_snapshot() { assert_eq!(compare("Maven", "1.0.1", "1.0-SNAPSHOT").unwrap(), 1); }
    #[test] fn maven_major_gt() { assert_eq!(compare("Maven", "2.0", "1.9.9").unwrap(), 1); }
    #[test] fn maven_alpha_seq() { assert_eq!(compare("Maven", "1.0-alpha-1", "1.0-alpha-2").unwrap(), -1); }
    #[test] fn maven_milestone_seq() { assert_eq!(compare("Maven", "1.0-m1", "1.0-m2").unwrap(), -1); }
    #[test] fn maven_cr_eq_rc() { assert_eq!(compare("Maven", "1.0-cr", "1.0-rc").unwrap(), 0); }

    // ====== DEBIAN — 10 golden cases ======

    #[test] fn debian_lt() { assert_eq!(compare("Debian", "1.0", "2.0").unwrap(), -1); }
    #[test] fn debian_epoch_gt() { assert_eq!(compare("Debian", "2:1.0", "1:9.9").unwrap(), 1); }
    #[test] fn debian_epoch_lt() { assert_eq!(compare("Debian", "1:1.0", "2:0.9").unwrap(), -1); }
    #[test] fn debian_tilde_lt() { assert_eq!(compare("Debian", "1.0~rc1", "1.0").unwrap(), -1); }
    #[test] fn debian_tilde_seq() { assert_eq!(compare("Debian", "1.0~beta", "1.0~rc1").unwrap(), -1); }
    #[test] fn debian_revision_lt() { assert_eq!(compare("Debian", "1.0-1", "1.0-2").unwrap(), -1); }
    #[test] fn debian_revision_gt() { assert_eq!(compare("Debian", "1.0-2", "1.0-1").unwrap(), 1); }
    #[test] fn debian_eq() { assert_eq!(compare("Debian", "2.3.4", "2.3.4").unwrap(), 0); }
    #[test] fn debian_tilde_after() { assert_eq!(compare("Debian", "1.0", "1.0~1").unwrap(), 1); }
    #[test] fn debian_alpha_lt_beta() { assert_eq!(compare("Debian", "1.0a", "1.0b").unwrap(), -1); }
    #[test] fn debian_alias() { assert_eq!(compare("debian", "1.0~rc1", "1.0").unwrap(), -1); }

    // ====== NUGET — 7 golden cases ======

    #[test] fn nuget_lt() { assert_eq!(compare("NuGet", "1.2.3", "1.2.4").unwrap(), -1); }
    #[test] fn nuget_pre_lt_release() { assert_eq!(compare("NuGet", "1.0.0-alpha", "1.0.0").unwrap(), -1); }
    #[test] fn nuget_pre_seq() { assert_eq!(compare("NuGet", "1.0.0-alpha", "1.0.0-beta").unwrap(), -1); }
    #[test] fn nuget_rc_seq() { assert_eq!(compare("NuGet", "1.0.0-rc.1", "1.0.0-rc.2").unwrap(), -1); }
    #[test] fn nuget_four_part() { assert_eq!(compare("NuGet", "1.2.3.4", "1.2.3.5").unwrap(), -1); }
    #[test] fn nuget_build_ignored() { assert_eq!(compare("NuGet", "1.0.0+meta", "1.0.0").unwrap(), 0); }
    #[test] fn nuget_v_prefix() { assert_eq!(compare("NuGet", "v1.0.0", "1.0.0").unwrap(), 0); }

    // ====== RUBYGEMS — 5 golden cases ======

    #[test] fn gem_pre_seq() { assert_eq!(compare("RubyGems", "1.0.0.pre1", "1.0.0.pre2").unwrap(), -1); }
    #[test] fn gem_pre_lt_release() { assert_eq!(compare("RubyGems", "1.0.0.pre2", "1.0.0").unwrap(), -1); }
    #[test] fn gem_trailing_zero() { assert_eq!(compare("RubyGems", "1.0.0", "1.0").unwrap(), 0); }
    #[test] fn gem_major_gt() { assert_eq!(compare("RubyGems", "2.0.0", "1.9.9").unwrap(), 1); }
    #[test] fn gem_alpha_lt_beta() { assert_eq!(compare("RubyGems", "1.0.0.alpha", "1.0.0.beta").unwrap(), -1); }

    // ====== COMPOSER / Packagist — 6 golden cases ======

    #[test] fn composer_lt() { assert_eq!(compare("Packagist", "1.2.3", "1.2.4").unwrap(), -1); }
    #[test] fn composer_alpha_lt_beta() { assert_eq!(compare("Packagist", "1.0.0-alpha", "1.0.0-beta").unwrap(), -1); }
    #[test] fn composer_beta_lt_rc() { assert_eq!(compare("Packagist", "1.0.0-beta", "1.0.0-rc").unwrap(), -1); }
    #[test] fn composer_rc_lt_release() { assert_eq!(compare("Packagist", "1.0.0-rc", "1.0.0").unwrap(), -1); }
    #[test] fn composer_dev_after_release() { assert_eq!(compare("Packagist", "1.0.0", "dev-master").unwrap(), -1); }
    #[test] fn composer_dev_lex() { assert_eq!(compare("Packagist", "dev-master", "dev-branch").unwrap(), 1); }

    // ====== IN_RANGE — 5 golden cases ======

    #[test] fn in_range_inside_fixed() {
        let events = vec![ev("introduced", "1.0.0"), ev("fixed", "2.0.0")];
        assert!(in_range("npm", "1.5.0", &events).unwrap());
    }
    #[test] fn in_range_below_lower() {
        let events = vec![ev("introduced", "1.0.0"), ev("fixed", "2.0.0")];
        assert!(!in_range("npm", "0.9.0", &events).unwrap());
    }
    #[test] fn in_range_at_fixed_exclusive() {
        let events = vec![ev("introduced", "1.0.0"), ev("fixed", "2.0.0")];
        assert!(!in_range("npm", "2.0.0", &events).unwrap());
    }
    #[test] fn in_range_last_affected_inclusive() {
        let events = vec![ev("introduced", "1.0.0"), ev("last_affected", "1.5.0")];
        assert!(in_range("npm", "1.5.0", &events).unwrap());
    }
    #[test] fn in_range_above_last_affected() {
        let events = vec![ev("introduced", "1.0.0"), ev("last_affected", "1.5.0")];
        assert!(!in_range("npm", "1.6.0", &events).unwrap());
    }

    // ====== ECOSYSTEM ALIASES — 4 cases ======

    #[test] fn alias_python() { assert_eq!(compare("python", "1.0a1", "1.0").unwrap(), -1); }
    #[test] fn alias_java() { assert_eq!(compare("java", "1.0-SNAPSHOT", "1.0").unwrap(), -1); }
    #[test] fn alias_cargo() { assert_eq!(compare("cargo", "1.2.3", "1.2.4").unwrap(), -1); }
    #[test] fn alias_deb() { assert_eq!(compare("deb", "1.0~rc1", "1.0").unwrap(), -1); }
}
