//! JSON utilities — JSONC parser, config-comment stripper, disk-backed cache.
//!
//! Faithful Rust port of the `core.json` Python package.
//!
//! Cycle note: Python `core.json.cache` lazily imports `core.tuning` to read
//! `max_json_memo_mb`. In Rust, to avoid a crate cycle, this crate exposes
//! `cache::set_max_memo_mb(u64)` so the tuning crate can inject the configured
//! value at startup without creating a dependency edge back into this crate.

pub mod cache;
pub mod jsonc;
pub mod utils;

// Re-export the most common public symbols at crate root for ergonomics
pub use cache::{set_max_memo_mb, CacheEnvelope, JsonCache, TTL_FOREVER};
pub use jsonc::{load_jsonc, strip_jsonc_comments};
pub use utils::{load_json, load_json_with_comments, save_json, strip_config_json_comments};

// ── PyO3 bindings ─────────────────────────────────────────────────────────────

#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;
    use pyo3::types::PyModule;

    /// Convert a `serde_json::Value` to a Python object tree.
    fn value_to_py(py: Python<'_>, v: serde_json::Value) -> PyResult<PyObject> {
        use serde_json::Value;
        match v {
            Value::Null => Ok(py.None()),
            Value::Bool(b) => Ok(b.into_py(py)),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(i.into_py(py))
                } else if let Some(f) = n.as_f64() {
                    Ok(f.into_py(py))
                } else {
                    Ok(n.to_string().into_py(py))
                }
            }
            Value::String(s) => Ok(s.into_py(py)),
            Value::Array(arr) => {
                let list = pyo3::types::PyList::empty_bound(py);
                for item in arr {
                    list.append(value_to_py(py, item)?)?;
                }
                Ok(list.into_py(py))
            }
            Value::Object(map) => {
                let dict = pyo3::types::PyDict::new_bound(py);
                for (k, v) in map {
                    dict.set_item(k, value_to_py(py, v)?)?;
                }
                Ok(dict.into_py(py))
            }
        }
    }

    // -- jsonc bindings --

    #[pyfunction]
    fn strip_jsonc_comments(text: &str) -> String {
        super::jsonc::strip_jsonc_comments(text)
    }

    #[pyfunction]
    fn load_jsonc(py: Python<'_>, text: &str) -> PyResult<PyObject> {
        super::jsonc::load_jsonc(text)
            .map(|v| value_to_py(py, v))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?
    }

    // -- utils bindings --

    #[pyfunction]
    fn load_json_with_comments(py: Python<'_>, path: &str) -> PyResult<PyObject> {
        let result = super::utils::load_json_with_comments(std::path::Path::new(path));
        match result {
            Some(v) => value_to_py(py, v),
            None => Ok(py.None()),
        }
    }

    #[pyfunction]
    fn load_json(py: Python<'_>, path: &str, strict: bool) -> PyResult<PyObject> {
        match super::utils::load_json(std::path::Path::new(path), strict) {
            Ok(Some(v)) => value_to_py(py, v),
            Ok(None) => Ok(py.None()),
            Err(e) => Err(pyo3::exceptions::PyOSError::new_err(e.to_string())),
        }
    }

    // -- cache bindings --

    #[pyfunction]
    fn set_max_memo_mb(mb: u64) {
        super::cache::set_max_memo_mb(mb);
    }

    #[pymodule]
    fn mantishack_core_json(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(strip_jsonc_comments, m)?)?;
        m.add_function(wrap_pyfunction!(load_jsonc, m)?)?;
        m.add_function(wrap_pyfunction!(load_json_with_comments, m)?)?;
        m.add_function(wrap_pyfunction!(load_json, m)?)?;
        m.add_function(wrap_pyfunction!(set_max_memo_mb, m)?)?;
        Ok(())
    }
}
