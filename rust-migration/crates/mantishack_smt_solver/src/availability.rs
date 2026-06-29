/// Z3 availability gate for MANTISHACK's SMT harness.
///
/// Z3 is an optional soft dependency. When the `z3` binary is not found in
/// PATH, `z3_available()` returns `false` and the `solve()` function in
/// `session` degrades gracefully with `SolverResult::Unknown(Z3NotFound)`.
///
/// This mirrors the Python `availability.py` behaviour:
/// - ImportError (z3 package missing) → false, debug log
/// - Other exception (package installed but broken) → false, warning log
/// Both map in Rust to: binary not found or non-zero exit → false.
use std::sync::OnceLock;

static Z3_AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Returns `true` when a `z3` binary is reachable and responds to `--version`.
///
/// Result is cached after the first call (lazy initialisation). The Python
/// equivalent is the module-level `_Z3_AVAILABLE` bool set at import time.
/// Rust caches on first call instead of at module load — semantically
/// identical for callers.
pub fn z3_available() -> bool {
    *Z3_AVAILABLE.get_or_init(probe_z3)
}

fn probe_z3() -> bool {
    std::process::Command::new("z3")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn z3_available_returns_bool_without_panic() {
        // Degradation test: must not panic regardless of whether z3 is installed.
        let _v: bool = z3_available();
    }

    #[test]
    fn z3_available_is_idempotent() {
        assert_eq!(z3_available(), z3_available());
    }
}
