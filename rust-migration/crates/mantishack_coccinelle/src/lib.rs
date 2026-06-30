//! Coccinelle (spatch) integration — faithful Rust port of `packages/coccinelle`.
//!
//! * [`models`]   — `SpatchMatch` / `SpatchResult` (`from_dict` / `to_dict` / `ok`).
//! * [`findings`] — `to_findings`: matches → MANTISHACK findings entries.
//! * [`coverage`] — `to_coverage_record`: results → coverage-coccinelle record.
//! * [`sarif`]    — `results_to_sarif`: results → SARIF 2.1.0 (+ `rel_to_repo`).
//! * [`prereqs`]  — `PrereqFacts` / `gather_prereqs` / `evaluate_finding`.
//! * [`runner`]   — the `spatch` subprocess driver (binary stays external) plus the
//!   pure `parse_results` / `parse_errors` / `dedup_matches` / `inject_harness` /
//!   `collect_files_examined` helpers.

pub mod coverage;
pub mod findings;
pub mod models;
pub mod prereqs;
pub mod runner;
pub mod sarif;

// Public surface mirroring the Python module names.
pub use coverage::to_coverage_record;
pub use findings::to_findings;
pub use models::{SpatchMatch, SpatchResult};
pub use prereqs::{evaluate_finding, gather_prereqs, PrereqFacts};
pub use runner::{is_available, run_rule, run_rules, version, RESULT_PREFIX};
pub use sarif::results_to_sarif;

#[cfg(test)]
mod tests;
