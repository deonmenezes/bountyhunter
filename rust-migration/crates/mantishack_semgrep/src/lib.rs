//! Semgrep integration — faithful Rust port of `packages/semgrep/`.
//!
//! This crate wraps the external `semgrep` binary via `std::process::Command`.
//! It owns argv construction and output parsing only; sandbox engagement, HOME
//! redirect, and parallel orchestration belong to the caller — the same division
//! that exists in the Python package.
//!
//! # Public API
//!
//! ```ignore
//! use mantishack_semgrep::{build_cmd, is_available, run_rule, run_rules, version};
//! use mantishack_semgrep::{SemgrepFinding, SemgrepResult};
//! use mantishack_semgrep::{to_findings, to_coverage_record};
//! use mantishack_semgrep::RunRuleArgs;
//! use std::path::Path;
//!
//! if is_available() {
//!     let result = run_rule(RunRuleArgs {
//!         target: Path::new("/src"),
//!         config: "p/security-audit",
//!         name: "",
//!         timeout: 900,
//!         rule_timeout: 60,
//!         env: None,
//!         json_output_path: None,
//!         semgrep_bin: None,
//!         extra_args: None,
//!     });
//!     for f in &result.findings {
//!         println!("{}:{}: {} — {}", f.file, f.line, f.rule_id, f.message);
//!     }
//! }
//! ```

pub mod coverage;
pub mod findings;
pub mod models;
pub mod runner;

// Re-export the public surface matching Python's `__init__.py __all__`.
pub use coverage::to_coverage_record;
pub use findings::to_findings;
pub use models::{parse_sarif, SemgrepFinding, SemgrepResult};
pub use runner::{build_cmd, config_to_name, get_safe_env, is_available, run_rule, run_rules, version, RunRuleArgs};

// ── PyO3 extension module ─────────────────────────────────────────────────────

#[cfg(feature = "python")]
mod python {
    use std::collections::HashMap;
    use std::path::Path;

    use pyo3::prelude::*;
    use pyo3::types::PyDict;

    use crate::models::{parse_sarif as rs_parse_sarif, SemgrepFinding as RsFinding, SemgrepResult as RsResult};
    use crate::runner::{
        build_cmd as rs_build_cmd, config_to_name as rs_config_to_name,
        get_safe_env as rs_get_safe_env, is_available as rs_is_available,
        run_rule as rs_run_rule, run_rules as rs_run_rules, version as rs_version,
        RunRuleArgs, DEFAULT_RULE_TIMEOUT, DEFAULT_TIMEOUT,
    };

    // ── Python-visible SemgrepFinding ─────────────────────────────────────────

    #[pyclass(name = "SemgrepFinding")]
    #[derive(Clone)]
    pub struct PySemgrepFinding {
        inner: RsFinding,
    }

    #[pymethods]
    impl PySemgrepFinding {
        #[getter] fn file(&self) -> &str { &self.inner.file }
        #[getter] fn line(&self) -> i64 { self.inner.line }
        #[getter] fn rule_id(&self) -> &str { &self.inner.rule_id }
        #[getter] fn message(&self) -> &str { &self.inner.message }
        #[getter] fn column(&self) -> i64 { self.inner.column }
        #[getter] fn line_end(&self) -> i64 { self.inner.line_end }
        #[getter] fn column_end(&self) -> i64 { self.inner.column_end }
        #[getter] fn level(&self) -> &str { &self.inner.level }

        fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
            let d = PyDict::new_bound(py);
            d.set_item("file",       &self.inner.file)?;
            d.set_item("line",       self.inner.line)?;
            d.set_item("column",     self.inner.column)?;
            d.set_item("line_end",   self.inner.line_end)?;
            d.set_item("column_end", self.inner.column_end)?;
            d.set_item("rule_id",    &self.inner.rule_id)?;
            d.set_item("message",    &self.inner.message)?;
            d.set_item("level",      &self.inner.level)?;
            Ok(d.into())
        }

        fn __repr__(&self) -> String {
            format!(
                "SemgrepFinding(file={:?}, line={}, rule_id={:?})",
                self.inner.file, self.inner.line, self.inner.rule_id
            )
        }
    }

    impl From<RsFinding> for PySemgrepFinding {
        fn from(f: RsFinding) -> Self { Self { inner: f } }
    }

    // ── Python-visible SemgrepResult ──────────────────────────────────────────

    #[pyclass(name = "SemgrepResult")]
    #[derive(Clone)]
    pub struct PySemgrepResult {
        inner: RsResult,
    }

    #[pymethods]
    impl PySemgrepResult {
        #[getter] fn name(&self) -> &str { &self.inner.name }
        #[getter] fn config(&self) -> &str { &self.inner.config }
        #[getter] fn target(&self) -> &str { &self.inner.target }
        #[getter] fn semgrep_version(&self) -> &str { &self.inner.semgrep_version }
        #[getter] fn returncode(&self) -> i32 { self.inner.returncode }
        #[getter] fn stderr(&self) -> &str { &self.inner.stderr }
        #[getter] fn sarif(&self) -> &str { &self.inner.sarif }
        #[getter] fn json_output(&self) -> &str { &self.inner.json_output }
        #[getter] fn elapsed_ms(&self) -> i64 { self.inner.elapsed_ms }
        #[getter] fn ok(&self) -> bool { self.inner.ok() }
        #[getter] fn finding_count(&self) -> usize { self.inner.finding_count() }

        #[getter]
        fn findings(&self) -> Vec<PySemgrepFinding> {
            self.inner.findings.iter().cloned().map(PySemgrepFinding::from).collect()
        }

        #[getter]
        fn files_examined(&self) -> Vec<String> {
            self.inner.files_examined.clone()
        }

        #[getter]
        fn errors(&self) -> Vec<String> {
            self.inner.errors.clone()
        }

        fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
            let json_str = self.inner.to_dict().to_string();
            let json_mod = py.import_bound("json")?;
            json_mod.call_method1("loads", (json_str,)).map(|v| v.into())
        }

        fn __repr__(&self) -> String {
            format!(
                "SemgrepResult(name={:?}, findings={}, returncode={})",
                self.inner.name,
                self.inner.findings.len(),
                self.inner.returncode
            )
        }
    }

    impl From<RsResult> for PySemgrepResult {
        fn from(r: RsResult) -> Self { Self { inner: r } }
    }

    // ── Python-visible free functions ─────────────────────────────────────────

    /// mirrors Python `is_available() -> bool`
    #[pyfunction]
    fn is_available() -> bool { rs_is_available() }

    /// mirrors Python `version() -> Optional[str]`
    #[pyfunction]
    fn version() -> Option<String> { rs_version() }

    /// mirrors Python `build_cmd(target, config, *, json_output_path=None,
    ///   rule_timeout=60, semgrep_bin=None, extra_args=None) -> List[str]`
    #[pyfunction]
    #[pyo3(signature = (target, config, json_output_path=None, rule_timeout=DEFAULT_RULE_TIMEOUT, semgrep_bin=None, extra_args=None))]
    fn build_cmd(
        target: &str,
        config: &str,
        json_output_path: Option<&str>,
        rule_timeout: u64,
        semgrep_bin: Option<&str>,
        extra_args: Option<Vec<String>>,
    ) -> Vec<String> {
        rs_build_cmd(
            Path::new(target),
            config,
            json_output_path.map(Path::new),
            rule_timeout,
            semgrep_bin,
            extra_args.as_deref(),
        )
    }

    /// mirrors Python `run_rule(target, config, *, name="", timeout=900,
    ///   rule_timeout=60, env=None, json_output_path=None, semgrep_bin=None,
    ///   extra_args=None, subprocess_runner=None) -> SemgrepResult`
    ///
    /// `subprocess_runner` is accepted but ignored — sandbox integration is the
    /// caller's responsibility in the Rust implementation.
    #[pyfunction]
    #[pyo3(signature = (
        target, config,
        name = "",
        timeout = DEFAULT_TIMEOUT,
        rule_timeout = DEFAULT_RULE_TIMEOUT,
        env = None,
        json_output_path = None,
        semgrep_bin = None,
        extra_args = None,
        subprocess_runner = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn run_rule(
        py: Python<'_>,
        target: &str,
        config: &str,
        name: &str,
        timeout: u64,
        rule_timeout: u64,
        env: Option<HashMap<String, String>>,
        json_output_path: Option<&str>,
        semgrep_bin: Option<&str>,
        extra_args: Option<Vec<String>>,
        subprocess_runner: Option<PyObject>,
    ) -> PySemgrepResult {
        let _ = (py, subprocess_runner); // subprocess_runner not used in Rust
        let result = rs_run_rule(RunRuleArgs {
            target: Path::new(target),
            config,
            name,
            timeout,
            rule_timeout,
            env: env.as_ref(),
            json_output_path: json_output_path.map(Path::new),
            semgrep_bin,
            extra_args: extra_args.as_deref(),
        });
        PySemgrepResult::from(result)
    }

    /// mirrors Python `run_rules(target, configs, ...) -> List[SemgrepResult]`
    #[pyfunction]
    #[pyo3(signature = (
        target, configs,
        timeout = DEFAULT_TIMEOUT,
        rule_timeout = DEFAULT_RULE_TIMEOUT,
        env = None,
        semgrep_bin = None,
        extra_args = None,
    ))]
    fn run_rules(
        target: &str,
        configs: Vec<(String, String)>,
        timeout: u64,
        rule_timeout: u64,
        env: Option<HashMap<String, String>>,
        semgrep_bin: Option<&str>,
        extra_args: Option<Vec<String>>,
    ) -> Vec<PySemgrepResult> {
        rs_run_rules(
            Path::new(target),
            &configs,
            timeout,
            rule_timeout,
            env.as_ref(),
            semgrep_bin,
            extra_args.as_deref(),
        )
        .into_iter()
        .map(PySemgrepResult::from)
        .collect()
    }

    /// mirrors Python `to_findings(results) -> List[dict]`
    #[pyfunction]
    fn to_findings(py: Python<'_>, results: Vec<PyRef<'_, PySemgrepResult>>) -> PyResult<PyObject> {
        let rs_results: Vec<RsResult> = results.iter().map(|r| r.inner.clone()).collect();
        let json_str = serde_json::to_string(&crate::to_findings(&rs_results))
            .unwrap_or_else(|_| "[]".to_string());
        let json_mod = py.import_bound("json")?;
        json_mod.call_method1("loads", (json_str,)).map(|v| v.into())
    }

    /// mirrors Python `to_coverage_record(results, *, rules_applied=None) -> Optional[dict]`
    #[pyfunction]
    #[pyo3(signature = (results, rules_applied = None))]
    fn to_coverage_record(
        py: Python<'_>,
        results: Vec<PyRef<'_, PySemgrepResult>>,
        rules_applied: Option<Vec<String>>,
    ) -> PyResult<PyObject> {
        let rs_results: Vec<RsResult> = results.iter().map(|r| r.inner.clone()).collect();
        match crate::to_coverage_record(&rs_results, rules_applied.as_deref()) {
            None => Ok(py.None()),
            Some(v) => {
                let json_str = serde_json::to_string(&v).unwrap_or_else(|_| "null".to_string());
                let json_mod = py.import_bound("json")?;
                json_mod.call_method1("loads", (json_str,)).map(|v| v.into())
            }
        }
    }

    /// mirrors Python `get_safe_env() -> Dict[str, str]`
    #[pyfunction]
    fn get_safe_env() -> HashMap<String, String> { rs_get_safe_env() }

    // ── Module registration ───────────────────────────────────────────────────

    #[pymodule]
    pub fn mantishack_semgrep(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_class::<PySemgrepFinding>()?;
        m.add_class::<PySemgrepResult>()?;
        m.add_function(wrap_pyfunction!(is_available, m)?)?;
        m.add_function(wrap_pyfunction!(version, m)?)?;
        m.add_function(wrap_pyfunction!(build_cmd, m)?)?;
        m.add_function(wrap_pyfunction!(run_rule, m)?)?;
        m.add_function(wrap_pyfunction!(run_rules, m)?)?;
        m.add_function(wrap_pyfunction!(to_findings, m)?)?;
        m.add_function(wrap_pyfunction!(to_coverage_record, m)?)?;
        m.add_function(wrap_pyfunction!(get_safe_env, m)?)?;
        Ok(())
    }
}

#[cfg(feature = "python")]
pub use python::mantishack_semgrep;

#[cfg(test)]
mod tests;
