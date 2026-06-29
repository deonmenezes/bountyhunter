//! First-class type for "the input bytes that triggered a bug."
//!
//! Faithful Rust port of the `core.witness` Python package.
//!
//! A `Witness` is the canonical artefact that captures *what was fed to a
//! target* and *what was observed* when it ran. Produced by multiple
//! pipelines (`/fuzz` crashes, `/crash-analysis` replays, `/validate` PoC
//! executions) and consumed by downstream features (reporting, scoring).
//!
//! The data model has two pieces:
//!
//! * [`Witness`] — the metadata record (bytes-hash + provenance + observed
//!   outcome). Carries a *reference* to the bytes via sha256 hash rather
//!   than inlining them.
//! * [`WitnessStore`] — hash-addressed blob storage at
//!   `{out_dir}/witnesses/`. Bytes are written once per unique hash
//!   (dedup across pipelines is automatic).
//!
//! Pipeline adapters live close to their producer rather than here.

pub mod discovery;
pub mod matching;
pub mod sandbox_outcome;
pub mod store;
pub mod types;

// ── Re-exports (mirrors core/witness/__init__.py __all__) ─────────────────────

pub use discovery::{discover_witness_stores, iter_visible_witnesses};
pub use matching::{best_match_for_finding, score_witness_for_finding, WitnessMatch};
pub use sandbox_outcome::outcome_from_sandbox_info;
pub use store::{WitnessStore, WitnessStoreError};
pub use types::{
    compute_bytes_hash, Witness, WitnessOutcome, WitnessSource, WitnessTypeError,
};

// ── PyO3 bindings ─────────────────────────────────────────────────────────────

#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;
    use pyo3::types::{PyBytes, PyModule, PyString};

    use crate::types::compute_bytes_hash;

    #[pyfunction]
    fn _compute_bytes_hash(py: Python<'_>, data: &[u8]) -> PyObject {
        let hex = compute_bytes_hash(data);
        PyString::new_bound(py, &hex).into()
    }

    #[pyclass(name = "WitnessStore")]
    struct PyWitnessStore {
        inner: crate::store::WitnessStore,
    }

    #[pymethods]
    impl PyWitnessStore {
        #[new]
        fn new(root: &str) -> Self {
            PyWitnessStore {
                inner: crate::store::WitnessStore::new(root),
            }
        }

        fn has(&self, bytes_hash: &str) -> bool {
            self.inner.has(bytes_hash)
        }

        fn get_bytes<'py>(&self, py: Python<'py>, bytes_hash: &str) -> PyResult<PyObject> {
            self.inner
                .get_bytes(bytes_hash)
                .map(|v| PyBytes::new_bound(py, &v).into())
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.0))
        }
    }

    #[pymodule]
    fn mantishack_core_witness(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(_compute_bytes_hash, m)?)?;
        m.add_class::<PyWitnessStore>()?;
        Ok(())
    }
}
