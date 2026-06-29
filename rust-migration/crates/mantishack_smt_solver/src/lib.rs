/// SMT solver framework for MANTISHACK — Rust port.
///
/// Faithful, behaviour-preserving port of `core/smt_solver/` (Python).
///
/// # Z3 invocation model
///
/// **Python**: uses the `z3-solver` Python package (in-process Z3 API).
/// Every function that creates a solver object (`new_solver`, `new_optimizer`),
/// adds constraints (`add`, `assert_and_track`), or reads models (`model()`)
/// calls directly into the Z3 C library via Python bindings.
///
/// **Rust**: Z3 is invoked as a subprocess via SMT-LIB2 text protocol.
/// - `solve(smtlib, timeout_ms) -> SolverResult` is the **external-tool seam**:
///   it writes SMT-LIB2 to z3's stdin and parses stdout.
/// - All constraint-construction logic is ported to SMT-LIB2 string builders
///   (`bitvec`, `csem` modules).
/// - `z3_available()` checks for the `z3` binary in PATH; when absent, every
///   `solve()` call returns `Unknown(Z3NotFound)` — the same graceful
///   degradation as Python's ImportError path.
///
/// # What is ported vs left as the external seam
///
/// | Python symbol | Rust equivalent | Where |
/// |---|---|---|
/// | `z3_available()` | `z3_available()` | `availability` |
/// | `BVProfile` | `BVProfile` | `config` |
/// | `mk_var/mk_val/le/lt/ge/gt` | same names → `SmtTerm` | `bitvec` |
/// | `canonicalise()` | `canonicalise()` | `canonicalise` |
/// | `Rejection`, `RejectionKind` | same | `rejection` |
/// | `propagate()` | `propagate()` | `rejection` |
/// | `parse_literal_value()` | `parse_literal_value()` | `rejection` |
/// | `classify_solver_unknown()` | `classify_solver_unknown()` | `rejection` |
/// | `DEFAULT_TIMEOUT_MS` | same | `session` |
/// | `new_solver(timeout_ms)` | `SolverSession::new()` + `check()` | `session` |
/// | `new_optimizer(timeout_ms)` | same seam (optimisation objectives TBD) | `session` |
/// | `scoped(solver)` | `SolverSession::scoped()` | `session` |
/// | `bv_to_int()` | `bv_to_int()` | `witness` |
/// | `format_witness()` | `parse_z3_model()` | `witness` |
/// | `track()`/`core_names()` | same | `explain` |
/// | `truncate/sign_extend/…` | same → `SmtTerm` | `csem` |
/// | `uadd_overflows/…` | same → `SmtTerm` | `csem` |
///
/// The actual Z3 solver call is the seam: `solve()` in `session.rs`.

pub mod availability;
pub mod bitvec;
pub mod canonicalise;
pub mod config;
pub mod csem;
pub mod explain;
pub mod rejection;
pub mod session;
pub mod witness;

// Re-export the public API mirroring Python's `__all__`.
pub use availability::z3_available;
pub use bitvec::{ge, gt, le, lt, mk_val, mk_var};
pub use canonicalise::canonicalise;
pub use config::{
    BVProfile, BV_AARCH64, BV_ARM32, BV_C_INT16, BV_C_INT32, BV_C_INT64, BV_C_INT8,
    BV_C_UINT16, BV_C_UINT32, BV_C_UINT64, BV_C_UINT8, BV_I386, BV_X86_64,
};
pub use explain::{core_names, track};
pub use rejection::{
    classify_solver_unknown, parse_literal_value, propagate, Rejection, RejectionKind,
};
pub use session::{clamp_timeout, solve, SolverResult, SolverSession, DEFAULT_TIMEOUT_MS};
pub use witness::{bv_to_int, parse_z3_model, SignednessMap};

// ---------------------------------------------------------------------------
// PyO3 Python module — feature-gated
// ---------------------------------------------------------------------------

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// Python module `mantishack_smt_solver`.
///
/// Exports all public symbols with identical names/signatures.
/// Feature-gated: only present when compiled with `--features python`.
#[cfg(feature = "python")]
#[pymodule]
fn mantishack_smt_solver(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Availability
    #[pyfunction]
    fn z3_available_py() -> bool {
        crate::availability::z3_available()
    }
    m.add_function(wrap_pyfunction!(z3_available_py, m)?)?;

    // canonicalise
    #[pyfunction]
    fn canonicalise_py(text: &str) -> String {
        crate::canonicalise::canonicalise(text)
    }
    m.add_function(wrap_pyfunction!(canonicalise_py, m)?)?;

    // BVProfile
    #[pyclass(name = "BVProfile")]
    #[derive(Clone)]
    struct PyBVProfile {
        inner: crate::config::BVProfile,
    }
    #[pymethods]
    impl PyBVProfile {
        #[new]
        #[pyo3(signature = (width=64, signed=false))]
        fn new(width: u32, signed: bool) -> PyResult<Self> {
            crate::config::BVProfile::new(width, signed)
                .map(|inner| PyBVProfile { inner })
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
        }
        #[getter]
        fn width(&self) -> u32 { self.inner.width }
        #[getter]
        fn signed(&self) -> bool { self.inner.signed }
        fn mode_tag(&self) -> String { self.inner.mode_tag() }
        fn describe(&self) -> String { self.inner.describe() }
    }
    m.add_class::<PyBVProfile>()?;

    // bv_to_int
    #[pyfunction]
    fn bv_to_int_py(raw: i64, width: u32, signed: bool) -> PyResult<i64> {
        crate::witness::bv_to_int(raw, width, signed)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
    }
    m.add_function(wrap_pyfunction!(bv_to_int_py, m)?)?;

    // DEFAULT_TIMEOUT_MS
    m.add("DEFAULT_TIMEOUT_MS", crate::session::DEFAULT_TIMEOUT_MS)?;

    // RejectionKind
    #[pyclass(name = "RejectionKind")]
    struct PyRejectionKind;
    // Export as string constants on the module (mirrors Python str+Enum).
    for kind in [
        crate::rejection::RejectionKind::LexEmpty,
        crate::rejection::RejectionKind::UnrecognizedForm,
        crate::rejection::RejectionKind::UnrecognizedOperand,
        crate::rejection::RejectionKind::UnsupportedOperator,
        crate::rejection::RejectionKind::UnbalancedParens,
        crate::rejection::RejectionKind::TrailingTokens,
        crate::rejection::RejectionKind::LiteralOutOfRange,
        crate::rejection::RejectionKind::LiteralAmbiguous,
        crate::rejection::RejectionKind::UnknownRegister,
        crate::rejection::RejectionKind::SolverTimeout,
        crate::rejection::RejectionKind::SolverUnknown,
        crate::rejection::RejectionKind::InputTooLong,
        crate::rejection::RejectionKind::TooManyConditions,
        crate::rejection::RejectionKind::AssignmentShaped,
    ] {
        m.add(
            &kind.as_str().to_ascii_uppercase().replace('-', "_"),
            kind.as_str(),
        )?;
    }

    // classify_solver_unknown
    #[pyfunction]
    fn classify_solver_unknown_py(reason: &str) -> String {
        crate::rejection::classify_solver_unknown(reason).to_string()
    }
    m.add_function(wrap_pyfunction!(classify_solver_unknown_py, m)?)?;

    Ok(())
}
