//! Source inventory and reachability analysis — Rust port of `core.inventory`.
//!
//! The crate is organized module-for-module with the Python package. Migration
//! is incremental inside this in-progress package; completed modules preserve
//! their Python data shapes through `serde_json::Value`.

pub mod build_membership;
pub mod call_graph;
pub mod coverage;
pub mod dead_scope;
pub mod diff;
pub mod extractors;
pub mod exclusions;
pub mod fixture_detection;
pub mod languages;
pub mod lookup;
pub mod module_load_abort;
pub mod reach_audit;
pub mod reach_cache;
pub mod reachability;
pub mod translation_view;
pub mod ts_extract;
pub mod reach_witness;

pub use build_membership::{
    crate_module_excluded, detect_build_excluded, tu_membership_excluded, BuildExcluded,
};
pub use coverage::{format_coverage_summary, get_coverage_stats, update_coverage};
pub use dead_scope::{detect_dead_scopes, DeadRange};
pub use diff::compare_inventories;
pub use exclusions::{
    is_binary_file, is_generated_file, match_exclusion_reason, should_exclude, DEFAULT_EXCLUDES,
    GENERATED_MARKERS, ROOT_ANCHORED_EXCLUDE_DIRS,
};
pub use extractors::{compute_interstitial_items, CodeItem};
pub use languages::{detect_language, LANGUAGE_MAP};
pub use lookup::{lookup_function, normalise_path};
pub use module_load_abort::{detect_module_load_abort, ModuleLoadAbort};
pub use reach_cache::{compute_fingerprint, is_valid_fingerprint, CACHE_VERSION};
pub use translation_view::{
    detect_macro_call_targets, detect_preprocessor_dead_ranges, preprocess_view, LineMap,
    MacroConfig, TranslationView, C_FAMILY,
};
pub use fixture_detection::{is_fixture_path, FixtureVerdict, HarnessEvidence};
pub use reach_witness::{
    blocker_for, prompt_verdict_for, verdict_from_classification, Reachability,
    ReachabilityVerdict, Soundness, VerdictSpec, Witness, WitnessKind,
    STRUCTURALLY_SUPPRESSIBLE_KINDS,
};

#[cfg(feature = "python")]
#[allow(clippy::useless_conversion)]
mod python {
    use std::path::PathBuf;

    use pyo3::prelude::*;
    use pyo3::types::PyModule;
    use serde_json::Value;

    fn py_to_json(value: &Bound<'_, PyAny>) -> PyResult<Value> {
        let json = PyModule::import_bound(value.py(), "json")?;
        let encoded: String = json.call_method1("dumps", (value,))?.extract()?;
        serde_json::from_str(&encoded)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))
    }

    fn json_to_py(py: Python<'_>, value: &Value) -> PyResult<PyObject> {
        let json = PyModule::import_bound(py, "json")?;
        let encoded = serde_json::to_string(value)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
        Ok(json.call_method1("loads", (encoded,))?.into())
    }

    #[pyfunction]
    fn detect_language(filepath: &str) -> Option<&'static str> {
        super::detect_language(filepath)
    }

    #[pyfunction]
    #[pyo3(signature = (filepath, sample_size=8192))]
    fn is_binary_file(filepath: PathBuf, sample_size: usize) -> bool {
        super::is_binary_file(&filepath, sample_size)
    }

    #[pyfunction]
    #[pyo3(signature = (content, check_lines=10))]
    fn is_generated_file(content: &str, check_lines: usize) -> bool {
        super::is_generated_file(content, check_lines)
    }

    #[pyfunction]
    fn should_exclude(filepath: &str, exclude_patterns: Vec<String>) -> bool {
        super::should_exclude(filepath, &exclude_patterns)
    }

    #[pyfunction]
    fn match_exclusion_reason(
        filepath: &str,
        exclude_patterns: Vec<String>,
    ) -> (bool, Option<&'static str>, Option<String>) {
        super::match_exclusion_reason(filepath, &exclude_patterns)
    }

    #[pyfunction]
    fn compare_inventories(
        py: Python<'_>,
        old: &Bound<'_, PyAny>,
        new: &Bound<'_, PyAny>,
    ) -> PyResult<Option<PyObject>> {
        let old = py_to_json(old)?;
        let new = py_to_json(new)?;
        super::compare_inventories(&old, &new)
            .as_ref()
            .map(|value| json_to_py(py, value))
            .transpose()
    }

    #[pyfunction]
    fn get_coverage_stats(py: Python<'_>, inventory: &Bound<'_, PyAny>) -> PyResult<PyObject> {
        let inventory = py_to_json(inventory)?;
        json_to_py(py, &super::get_coverage_stats(&inventory))
    }

    #[pyfunction]
    fn format_coverage_summary(inventory: &Bound<'_, PyAny>) -> PyResult<String> {
        Ok(super::format_coverage_summary(&py_to_json(inventory)?))
    }

    #[pyfunction]
    fn update_coverage(
        py: Python<'_>,
        inventory: &Bound<'_, PyAny>,
        checked_functions: &Bound<'_, PyAny>,
        source_label: &str,
    ) -> PyResult<PyObject> {
        let mut inventory_value = py_to_json(inventory)?;
        let checked_functions = py_to_json(checked_functions)?;
        super::update_coverage(&mut inventory_value, &checked_functions, source_label);

        // Preserve the Python API's in-place mutation for dict callers.
        if let Ok(dict) = inventory.downcast::<pyo3::types::PyDict>() {
            let replacement = json_to_py(py, &inventory_value)?;
            let replacement = replacement.bind(py).downcast::<pyo3::types::PyDict>()?;
            dict.clear();
            dict.update(replacement.as_mapping())?;
            return Ok(dict.clone().into());
        }
        json_to_py(py, &inventory_value)
    }

    #[pyfunction]
    fn normalise_path(path: &str, repo_root: &str) -> String {
        super::normalise_path(path, repo_root)
    }

    #[pyfunction]
    fn detect_dead_scopes(language: &str, content: &str) -> Vec<(usize, usize)> {
        super::detect_dead_scopes(language, content)
    }

    #[pyfunction]
    #[pyo3(signature = (checklist, file_path, line, repo_root=""))]
    fn lookup_function(
        py: Python<'_>,
        checklist: &Bound<'_, PyAny>,
        file_path: &str,
        line: i64,
        repo_root: &str,
    ) -> PyResult<Option<PyObject>> {
        if checklist.is_none() {
            return Ok(None);
        }
        let checklist = py_to_json(checklist)?;
        let result = super::lookup_function(&checklist, file_path, line, repo_root)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        result
            .as_ref()
            .map(|value| json_to_py(py, value))
            .transpose()
    }

    #[pymodule]
    pub fn mantishack_core_inventory(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add("LANGUAGE_MAP", super::languages::language_map_py(m.py())?)?;
        m.add("DEFAULT_EXCLUDES", super::DEFAULT_EXCLUDES.to_vec())?;
        m.add("GENERATED_MARKERS", super::GENERATED_MARKERS.to_vec())?;
        m.add_function(wrap_pyfunction!(detect_language, m)?)?;
        m.add_function(wrap_pyfunction!(is_binary_file, m)?)?;
        m.add_function(wrap_pyfunction!(is_generated_file, m)?)?;
        m.add_function(wrap_pyfunction!(should_exclude, m)?)?;
        m.add_function(wrap_pyfunction!(match_exclusion_reason, m)?)?;
        m.add_function(wrap_pyfunction!(compare_inventories, m)?)?;
        m.add_function(wrap_pyfunction!(update_coverage, m)?)?;
        m.add_function(wrap_pyfunction!(get_coverage_stats, m)?)?;
        m.add_function(wrap_pyfunction!(format_coverage_summary, m)?)?;
        m.add_function(wrap_pyfunction!(normalise_path, m)?)?;
        m.add_function(wrap_pyfunction!(lookup_function, m)?)?;
        m.add_function(wrap_pyfunction!(detect_dead_scopes, m)?)?;
        Ok(())
    }
}

#[cfg(feature = "python")]
pub use python::mantishack_core_inventory;
