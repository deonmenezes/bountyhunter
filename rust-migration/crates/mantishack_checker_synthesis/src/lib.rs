//! KNighter-style checker synthesis — Rust port of the PURE surface of
//! `packages/checker_synthesis`. See the module docs for exactly what is ported
//! versus what stays Python by design (LLM calls, scanner subprocesses, the
//! atomic rule-file write, and the synthesise/refinement orchestration loops).

pub mod languages;
pub mod models;
pub mod prompts;
pub mod synthesise;

pub use languages::{detect_engine, supported_engines};
pub use models::{
    CheckerSynthesisResult, Match, MatchTriage, SeedBug, SynthesisedRule, TRIAGE_STATUSES,
};
pub use prompts::{
    build_synthesis_prompt, build_triage_prompt, synthesis_schema, triage_schema, truncate_snippet,
    SYNTHESIS_SYSTEM, TRIAGE_SYSTEM,
};
pub use synthesise::{
    fp_rate, is_seed_match, make_rule_id, rule_extension, slugify, validate_rule_body,
    validate_seed_path, RULE_BODY_MAX_BYTES, RULE_BODY_MAX_LINE, RULE_TOO_LOOSE_THRESHOLD,
    SEED_SNIPPET_MAX_BYTES,
};

// PyO3 binding for the deterministic pure surface. The model dataclasses,
// prompt builders, and orchestration are wired in a follow-up (see the crate's
// migration-state note); this exposes the primitive-in/primitive-out helpers
// and string/int constants Python callers can already switch to.
#[cfg(feature = "python")]
#[allow(unexpected_cfgs)]
mod python {
    use pyo3::prelude::*;

    #[pyfunction]
    fn detect_engine(file_path: &str) -> Option<&'static str> {
        crate::languages::detect_engine(file_path)
    }

    #[pyfunction]
    fn supported_engines() -> (&'static str, &'static str) {
        crate::languages::supported_engines()
    }

    #[pyfunction]
    fn slugify(value: &str) -> String {
        crate::synthesise::slugify(value)
    }

    #[pyfunction]
    fn rule_extension(engine: &str) -> &'static str {
        crate::synthesise::rule_extension(engine)
    }

    #[pyfunction]
    fn validate_seed_path(file_path: &str) -> Option<String> {
        crate::synthesise::validate_seed_path(file_path)
    }

    #[pyfunction]
    fn validate_rule_body(body: &str) -> Option<String> {
        crate::synthesise::validate_rule_body(body)
    }

    #[pyfunction]
    fn truncate_snippet(snippet: &str) -> String {
        crate::prompts::truncate_snippet(snippet)
    }

    #[pymodule]
    fn mantishack_checker_synthesis(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(detect_engine, m)?)?;
        m.add_function(wrap_pyfunction!(supported_engines, m)?)?;
        m.add_function(wrap_pyfunction!(slugify, m)?)?;
        m.add_function(wrap_pyfunction!(rule_extension, m)?)?;
        m.add_function(wrap_pyfunction!(validate_seed_path, m)?)?;
        m.add_function(wrap_pyfunction!(validate_rule_body, m)?)?;
        m.add_function(wrap_pyfunction!(truncate_snippet, m)?)?;
        m.add("SYNTHESIS_SYSTEM", crate::prompts::SYNTHESIS_SYSTEM)?;
        m.add("TRIAGE_SYSTEM", crate::prompts::TRIAGE_SYSTEM)?;
        m.add("TRIAGE_STATUSES", crate::models::TRIAGE_STATUSES)?;
        m.add("RULE_BODY_MAX_BYTES", crate::synthesise::RULE_BODY_MAX_BYTES)?;
        m.add("RULE_BODY_MAX_LINE", crate::synthesise::RULE_BODY_MAX_LINE)?;
        m.add("SEED_SNIPPET_MAX_BYTES", crate::synthesise::SEED_SNIPPET_MAX_BYTES)?;
        m.add("RULE_TOO_LOOSE_THRESHOLD", crate::synthesise::RULE_TOO_LOOSE_THRESHOLD)?;
        Ok(())
    }
}
