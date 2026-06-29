//! CodeQL CLI detection and configuration — faithful Rust port of
//! `packages/static-analysis/codeql/env.py`.
//!
//! # Module
//! * [`env`] — port of `env.py`: [`env::CodeQLEnv`], [`env::detect_codeql`],
//!   [`env::run_codeql_version`].
//!
//! # Example
//! ```no_run
//! use mantishack_static_codeql::{detect_codeql, CodeQLEnv};
//!
//! let cql = detect_codeql(Some("detect"));
//! if cql.available {
//!     println!("CodeQL {} at {:?}", cql.version.unwrap(), cql.cli_path);
//! }
//! ```

pub mod env;

// Re-export the public surface matching Python's module-level names.
pub use env::{detect_codeql, run_codeql_version, CodeQLEnv, UNSAFE_ENV_KEYS};

// ── PyO3 extension module ─────────────────────────────────────────────────────

#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;
    use pyo3::types::PyDict;

    use crate::env::{detect_codeql as rs_detect, CodeQLEnv as RsEnv};

    // ── Python-visible CodeQLEnv ──────────────────────────────────────────────

    #[pyclass(name = "CodeQLEnv")]
    #[derive(Clone)]
    pub struct PyCodeQLEnv {
        inner: RsEnv,
    }

    #[pymethods]
    impl PyCodeQLEnv {
        #[getter]
        fn mode(&self) -> &str { &self.inner.mode }
        #[getter]
        fn available(&self) -> bool { self.inner.available }
        #[getter]
        fn cli_path(&self) -> Option<&str> { self.inner.cli_path.as_deref() }
        #[getter]
        fn version(&self) -> Option<&str> { self.inner.version.as_deref() }
        #[getter]
        fn queries(&self) -> Option<&str> { self.inner.queries.as_deref() }
        #[getter]
        fn reason(&self) -> Option<&str> { self.inner.reason.as_deref() }

        /// Mirrors Python `CodeQLEnv.to_dict()` — returns a plain Python dict.
        fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
            let d = PyDict::new_bound(py);
            d.set_item("mode", &self.inner.mode)?;
            d.set_item("available", self.inner.available)?;
            d.set_item("cli_path", self.inner.cli_path.as_deref())?;
            d.set_item("version", self.inner.version.as_deref())?;
            d.set_item("queries", self.inner.queries.as_deref())?;
            d.set_item("reason", self.inner.reason.as_deref())?;
            Ok(d.into())
        }

        fn __repr__(&self) -> String {
            format!(
                "CodeQLEnv(mode={:?}, available={}, cli_path={:?})",
                self.inner.mode, self.inner.available, self.inner.cli_path
            )
        }
    }

    impl From<RsEnv> for PyCodeQLEnv {
        fn from(e: RsEnv) -> Self { Self { inner: e } }
    }

    // ── Python-visible free functions ─────────────────────────────────────────

    /// mirrors Python `detect_codeql(mode: CodeQLMode = "detect") -> CodeQLEnv`
    #[pyfunction]
    #[pyo3(signature = (mode = "detect"))]
    fn detect_codeql(mode: &str) -> PyCodeQLEnv {
        PyCodeQLEnv::from(rs_detect(Some(mode)))
    }

    // ── Module registration ───────────────────────────────────────────────────

    #[pymodule]
    pub fn mantishack_static_codeql(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_class::<PyCodeQLEnv>()?;
        m.add_function(wrap_pyfunction!(detect_codeql, m)?)?;
        Ok(())
    }
}

#[cfg(feature = "python")]
pub use python::mantishack_static_codeql;

#[cfg(test)]
mod tests;
