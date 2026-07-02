//! Faithful Rust port of `core/security/` security-critical primitives.
//!
//! Ported modules (behaviour-preserving — same inputs, same outputs):
//!   * [`env_sanitisation`] — `strip_env_vars` / `intersect_env_vars`.
//!   * [`cc_trust`] — Claude Code config trust scanner + dangerous-env
//!     detection. Holds the comprehensive dangerous-env set and the
//!     [`cc_trust::set_config_dangerous_env_vars`] **injection point** that
//!     breaks the Python config↔security import cycle.
//!   * [`codeql_trust`] — CodeQL pack trust scanner + path-traversal defenses.
//!
//! The heavier prompt-injection modules under `core/security/` (prompt_envelope*,
//! llm_family, redaction, envelope_probe, prompt_telemetry, …) are not part of
//! the config↔security runtime cycle nor the parity oracle and are out of scope
//! for this crate.

pub mod cc_trust;
pub mod codeql_trust;
pub mod env_sanitisation;
pub mod log_sanitisation;
pub mod prompt_envelope;
pub mod pyval;

// ───────────────────────── PyO3 bindings ───────────────────────────────────

#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;
    use pyo3::types::{PyDict, PyList, PyModule};

    fn key_strings(names: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
        let mut out = Vec::new();
        for item in names.iter()? {
            out.push(item?.extract::<String>()?);
        }
        Ok(out)
    }

    /// `strip_env_vars(env, names) -> dict` — order-preserving key removal.
    #[pyfunction]
    fn strip_env_vars<'py>(
        py: Python<'py>,
        env: &Bound<'py, PyDict>,
        names: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let block = key_strings(names)?;
        let block: std::collections::HashSet<String> = block.into_iter().collect();
        let out = PyDict::new_bound(py);
        for (k, v) in env.iter() {
            let ks: String = k.extract()?;
            if !block.contains(&ks) {
                out.set_item(k, v)?;
            }
        }
        Ok(out)
    }

    /// `intersect_env_vars(env, names) -> sorted list`.
    #[pyfunction]
    fn intersect_env_vars<'py>(
        py: Python<'py>,
        env: &Bound<'py, PyDict>,
        names: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyList>> {
        let block: std::collections::HashSet<String> = key_strings(names)?.into_iter().collect();
        let mut present: Vec<String> = Vec::new();
        for (k, _) in env.iter() {
            let ks: String = k.extract()?;
            if block.contains(&ks) {
                present.push(ks);
            }
        }
        present.sort();
        Ok(PyList::new_bound(py, present))
    }

    // cc_trust bindings.
    #[pyfunction]
    #[pyo3(name = "set_trust_override")]
    fn cc_set_trust_override(val: bool) {
        super::cc_trust::set_trust_override(val);
    }

    #[pyfunction]
    fn is_trust_overridden() -> bool {
        super::cc_trust::is_trust_overridden()
    }

    #[pyfunction]
    #[pyo3(signature = (repo_path, trust_override=None))]
    fn check_repo_claude_trust(repo_path: &str, trust_override: Option<bool>) -> bool {
        super::cc_trust::check_repo_claude_trust(repo_path, trust_override)
    }

    // codeql_trust bindings.
    #[pyfunction]
    #[pyo3(name = "codeql_set_trust_override")]
    fn codeql_set_trust_override(val: bool) {
        super::codeql_trust::set_trust_override(val);
    }

    #[pyfunction]
    #[pyo3(signature = (repo_path, trust_override=None))]
    fn check_repo_codeql_trust(repo_path: &str, trust_override: Option<bool>) -> bool {
        super::codeql_trust::check_repo_codeql_trust(repo_path, trust_override)
    }

    /// `escape_nonprintable(s, *, preserve_newlines=False) -> str`.
    #[pyfunction]
    #[pyo3(signature = (s, *, preserve_newlines=false))]
    fn escape_nonprintable(s: &str, preserve_newlines: bool) -> String {
        super::log_sanitisation::escape_nonprintable(s, preserve_newlines)
    }

    /// `has_nonprintable(s) -> bool`.
    #[pyfunction]
    fn has_nonprintable(s: &str) -> bool {
        super::log_sanitisation::has_nonprintable(s)
    }

    #[pymodule]
    fn mantishack_core_security(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(strip_env_vars, m)?)?;
        m.add_function(wrap_pyfunction!(intersect_env_vars, m)?)?;
        m.add_function(wrap_pyfunction!(escape_nonprintable, m)?)?;
        m.add_function(wrap_pyfunction!(has_nonprintable, m)?)?;
        m.add_function(wrap_pyfunction!(cc_set_trust_override, m)?)?;
        m.add_function(wrap_pyfunction!(is_trust_overridden, m)?)?;
        m.add_function(wrap_pyfunction!(check_repo_claude_trust, m)?)?;
        m.add_function(wrap_pyfunction!(codeql_set_trust_override, m)?)?;
        m.add_function(wrap_pyfunction!(check_repo_codeql_trust, m)?)?;
        Ok(())
    }
}
