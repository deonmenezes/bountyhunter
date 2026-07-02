//! Structured per-function AST views — Rust port of the `core.ast` package.
//!
//! The inventory substrate (`mantishack_core_inventory`) answers file-level
//! questions ("what functions exist?", "what does this file call?"). `core.ast`
//! answers the per-function question: "what is the shape of *this one*
//! function?" — its signature, the calls it makes, where it returns, and whether
//! it embeds inline asm.
//!
//! This is a **composition layer**, not new parsing infrastructure: it reuses
//! the per-language tree-sitter walkers and call-graph extractors already ported
//! in `mantishack_core_inventory`, adding only per-function returns + inline-asm
//! detection on top.
//!
//! Module map (module-for-module with the Python package):
//!
//!   * `model`  — `core/ast/model.py`  ([`FunctionView`], [`Return`], re-exported
//!     [`CallSite`], [`SCHEMA_VERSION`]).
//!   * `view`   — `core/ast/view.py`   ([`view`]).
//!   * this file — `core/ast/__init__.py` (public re-exports + the `#[pymodule]`).
//!
//! Language coverage matches the Python revision: calls+returns+asm for C/C++;
//! calls+returns for Python/JavaScript/Java/Go; calls-only (inherited from
//! inventory) for Rust/Ruby/C#/PHP/TypeScript.

pub mod model;
pub mod view;

pub use model::{CallSite, FunctionView, Return, SCHEMA_VERSION};
pub use view::view;

// ── PyO3 bindings ─────────────────────────────────────────────────────────────
//
// Signature-identical to `core.ast`: Python callers switch by changing one
// import line. Gated behind the `python` feature so the parity oracle
// (`cargo test`, default features) builds without linking libpython.

#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;
    use pyo3::types::PyModule;
    use std::path::PathBuf;

    use crate::model::{CallSite, FunctionView, Return, SCHEMA_VERSION};

    fn json_to_py(py: Python<'_>, value: &serde_json::Value) -> PyResult<PyObject> {
        let json = PyModule::import_bound(py, "json")?;
        let encoded = serde_json::to_string(value)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(json.call_method1("loads", (encoded,))?.into())
    }

    #[pyclass(name = "Return")]
    #[derive(Clone)]
    struct PyReturn {
        inner: Return,
    }

    #[pymethods]
    impl PyReturn {
        #[getter]
        fn line(&self) -> i64 {
            self.inner.line
        }
        #[getter]
        fn value_text(&self) -> String {
            self.inner.value_text.clone()
        }
    }

    #[pyclass(name = "CallSite")]
    #[derive(Clone)]
    struct PyCallSite {
        inner: CallSite,
    }

    #[pymethods]
    impl PyCallSite {
        #[getter]
        fn line(&self) -> i64 {
            self.inner.line
        }
        #[getter]
        fn chain(&self) -> Vec<String> {
            self.inner.chain.clone()
        }
        #[getter]
        fn caller(&self) -> Option<String> {
            self.inner.caller.clone()
        }
        #[getter]
        fn receiver_class(&self) -> Option<String> {
            self.inner.receiver_class.clone()
        }
        #[getter]
        fn receiver_type(&self) -> Option<String> {
            self.inner.receiver_type.clone()
        }
        #[getter]
        fn argument_identifiers(&self) -> Vec<String> {
            self.inner.argument_identifiers.clone()
        }
    }

    #[pyclass(name = "FunctionView")]
    #[derive(Clone)]
    struct PyFunctionView {
        inner: FunctionView,
    }

    #[pymethods]
    impl PyFunctionView {
        #[getter]
        fn function(&self) -> String {
            self.inner.function.clone()
        }
        #[getter]
        fn file(&self) -> String {
            self.inner.file.clone()
        }
        #[getter]
        fn language(&self) -> String {
            self.inner.language.clone()
        }
        #[getter]
        fn lines(&self) -> (i64, i64) {
            self.inner.lines
        }
        #[getter]
        fn signature(&self) -> String {
            self.inner.signature.clone()
        }
        #[getter]
        fn calls_made(&self) -> Vec<PyCallSite> {
            self.inner
                .calls_made
                .iter()
                .map(|c| PyCallSite { inner: c.clone() })
                .collect()
        }
        #[getter]
        fn returns(&self) -> Vec<PyReturn> {
            self.inner
                .returns
                .iter()
                .map(|r| PyReturn { inner: r.clone() })
                .collect()
        }
        #[getter]
        fn has_inline_asm(&self) -> bool {
            self.inner.has_inline_asm
        }
        #[getter]
        fn schema_version(&self) -> i64 {
            self.inner.schema_version
        }

        fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
            json_to_py(py, &self.inner.to_json())
        }
    }

    #[pyfunction]
    #[pyo3(signature = (path, function, *, at_line=None, language=None))]
    fn view(
        path: PathBuf,
        function: &str,
        at_line: Option<i64>,
        language: Option<&str>,
    ) -> Option<PyFunctionView> {
        crate::view::view(&path, function, at_line, language)
            .map(|fv| PyFunctionView { inner: fv })
    }

    #[pymodule]
    pub fn mantishack_core_ast(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add("SCHEMA_VERSION", SCHEMA_VERSION)?;
        m.add_class::<PyReturn>()?;
        m.add_class::<PyCallSite>()?;
        m.add_class::<PyFunctionView>()?;
        m.add_function(wrap_pyfunction!(view, m)?)?;
        Ok(())
    }
}

#[cfg(feature = "python")]
pub use python::mantishack_core_ast;
