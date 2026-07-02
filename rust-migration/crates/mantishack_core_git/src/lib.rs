//! Faithful Rust port of `core/git/` — sandbox-routed clone / fetch / ls-remote
//! plus the repository-URL allowlist.
//!
//! Ported modules (behaviour-preserving — same inputs, same outputs, same
//! ordering, same reject/accept decisions):
//!   * [`validate`] — `validate_repo_url`, the fail-closed github/gitlab HTTPS +
//!     SSH URL allowlist (regex with the `..`-forbidding lookahead).
//!   * [`proxy_hosts`] — `proxy_hosts_for_git` two-layer resolution (operator
//!     override JSON → static public-forge default).
//!   * [`clone`] — the PURE, security-load-bearing decision logic the three
//!     I/O entry points gate on: caller-SHA / ls-remote-SHA shape checks, the
//!     writable-path validator, the `-c key=value` safe-git overrides, the git
//!     argv builders (clone / init / remote / fetch / ls-remote), the
//!     `ls_remote` URL validator, and the `ls-remote` output parser.
//!
//! **Stays in Python by design (I/O-bound; not faked here):** the three public
//! wrappers `clone_repository` / `fetch_commit` / `ls_remote` spawn `git`
//! through `core.sandbox.run_untrusted`, emit credential-redacted log lines
//! (`core.security.redaction`), build the sanitised env
//! (`MantishackConfig.get_git_env`, already ported in `mantishack_core_config`),
//! and enforce the bounded `GIT_CLONE_TIMEOUT`. Those wrappers now delegate the
//! validation / arg-building / parsing to this crate.
//!
//! One flagged approximation: IDNA punycode canonicalisation of *non-ASCII* IDN
//! hostnames in [`clone::validate_ls_remote_url`] is not byte-reproduced
//! (untested by the parity oracle; ASCII hosts — every tested input and the
//! common case — are handled identically; the egress proxy re-checks the
//! allowlist at runtime regardless). See that function's docs.

pub mod clone;
pub mod proxy_hosts;
pub mod urlparse;
pub mod validate;

// Re-exports mirroring `core/git/__init__.py`'s public surface (pure pieces).
pub use proxy_hosts::proxy_hosts_for_git;
pub use validate::validate_repo_url;

// ───────────────────────────── PyO3 bindings ───────────────────────────────

#[cfg(feature = "python")]
mod python {
    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;
    use pyo3::types::PyModule;

    /// `validate_repo_url(url) -> bool`.
    #[pyfunction]
    fn validate_repo_url(url: &str) -> bool {
        crate::validate::validate_repo_url(url)
    }

    /// `proxy_hosts_for_git() -> list[str]`.
    #[pyfunction]
    fn proxy_hosts_for_git() -> Vec<String> {
        crate::proxy_hosts::proxy_hosts_for_git()
    }

    /// Caller-supplied SHA shape check (`[0-9a-fA-F]{4,40}`).
    #[pyfunction]
    fn is_valid_sha(sha: &str) -> bool {
        crate::clone::is_valid_sha(sha)
    }

    /// Strict 40-hex `ls-remote` output SHA check.
    #[pyfunction]
    fn is_ls_remote_sha(sha: &str) -> bool {
        crate::clone::is_ls_remote_sha(sha)
    }

    /// `safe_git_command(*args) -> list[str]`.
    #[pyfunction]
    #[pyo3(signature = (*args))]
    fn safe_git_command(args: Vec<String>) -> Vec<String> {
        crate::clone::safe_git_command(&args)
    }

    /// `build_clone_cmd(url, target, depth=1) -> list[str]`.
    #[pyfunction]
    #[pyo3(signature = (url, target, depth=Some(1)))]
    fn build_clone_cmd(url: &str, target: &str, depth: Option<i64>) -> Vec<String> {
        crate::clone::build_clone_cmd(url, target, depth)
    }

    /// `build_init_cmd(repo_dir) -> list[str]`.
    #[pyfunction]
    fn build_init_cmd(repo_dir: &str) -> Vec<String> {
        crate::clone::build_init_cmd(repo_dir)
    }

    /// `build_remote_add_cmd(repo_dir, url) -> list[str]`.
    #[pyfunction]
    fn build_remote_add_cmd(repo_dir: &str, url: &str) -> Vec<String> {
        crate::clone::build_remote_add_cmd(repo_dir, url)
    }

    /// `build_remote_set_url_cmd(repo_dir, url) -> list[str]`.
    #[pyfunction]
    fn build_remote_set_url_cmd(repo_dir: &str, url: &str) -> Vec<String> {
        crate::clone::build_remote_set_url_cmd(repo_dir, url)
    }

    /// `build_fetch_cmd(repo_dir, sha, depth=5) -> list[str]`.
    #[pyfunction]
    #[pyo3(signature = (repo_dir, sha, depth=5))]
    fn build_fetch_cmd(repo_dir: &str, sha: &str, depth: i64) -> Vec<String> {
        crate::clone::build_fetch_cmd(repo_dir, sha, depth)
    }

    /// `build_ls_remote_cmd(url) -> list[str]`.
    #[pyfunction]
    fn build_ls_remote_cmd(url: &str) -> Vec<String> {
        crate::clone::build_ls_remote_cmd(url)
    }

    /// `validate_writable_path(path, role) -> None`; raises `ValueError`.
    #[pyfunction]
    fn validate_writable_path(path: &str, role: &str) -> PyResult<()> {
        crate::clone::validate_writable_path(std::path::Path::new(path), role)
            .map_err(|e| PyValueError::new_err(e.0))
    }

    /// `validate_ls_remote_url(url, proxy_hosts) -> str`; raises `ValueError`.
    #[pyfunction]
    fn validate_ls_remote_url(url: &str, proxy_hosts: Vec<String>) -> PyResult<String> {
        crate::clone::validate_ls_remote_url(url, &proxy_hosts)
            .map_err(|e| PyValueError::new_err(e.0))
    }

    /// `parse_ls_remote_output(stdout) -> list[tuple[str, str]]`.
    #[pyfunction]
    fn parse_ls_remote_output(stdout: &str) -> Vec<(String, String)> {
        crate::clone::parse_ls_remote_output(stdout)
    }

    #[pymodule]
    fn mantishack_core_git(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(validate_repo_url, m)?)?;
        m.add_function(wrap_pyfunction!(proxy_hosts_for_git, m)?)?;
        m.add_function(wrap_pyfunction!(is_valid_sha, m)?)?;
        m.add_function(wrap_pyfunction!(is_ls_remote_sha, m)?)?;
        m.add_function(wrap_pyfunction!(safe_git_command, m)?)?;
        m.add_function(wrap_pyfunction!(build_clone_cmd, m)?)?;
        m.add_function(wrap_pyfunction!(build_init_cmd, m)?)?;
        m.add_function(wrap_pyfunction!(build_remote_add_cmd, m)?)?;
        m.add_function(wrap_pyfunction!(build_remote_set_url_cmd, m)?)?;
        m.add_function(wrap_pyfunction!(build_fetch_cmd, m)?)?;
        m.add_function(wrap_pyfunction!(build_ls_remote_cmd, m)?)?;
        m.add_function(wrap_pyfunction!(validate_writable_path, m)?)?;
        m.add_function(wrap_pyfunction!(validate_ls_remote_url, m)?)?;
        m.add_function(wrap_pyfunction!(parse_ls_remote_output, m)?)?;
        Ok(())
    }
}
