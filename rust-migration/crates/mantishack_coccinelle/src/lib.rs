//! Coccinelle (spatch) result handling — partial Rust port of the
//! `packages/coccinelle` package.
//!
//! Ported (pure, deterministic, golden-vector verified against the Python oracle):
//! * [`models`]   — `SpatchMatch` / `SpatchResult` (`from_dict` / `to_dict` / `ok`).
//! * [`findings`] — `to_findings`: matches → MANTISHACK findings entries.
//! * [`coverage`] — `to_coverage_record`: results → coverage-coccinelle record.
//!
//! Pending (the "binary stays" glue + filesystem-coupled surface):
//! * `sarif`   — `results_to_sarif` (`_rel_to_repo` leans on Python `Path.resolve()`).
//! * `prereqs` — `gather_prereqs` / `evaluate_finding` (runs spatch, walks the tree).
//! * `runner`  — the `spatch` subprocess driver itself.

pub mod coverage;
pub mod findings;
pub mod models;

// Public surface mirroring the Python module names.
pub use coverage::to_coverage_record;
pub use findings::to_findings;
pub use models::{SpatchMatch, SpatchResult};

#[cfg(test)]
mod tests;
