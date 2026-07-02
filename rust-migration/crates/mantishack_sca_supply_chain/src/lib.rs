//! Supply-chain heuristics — Rust port of `packages/sca/supply_chain/`.
//!
//! `typosquat` (Damerau-Levenshtein candidate detection over bundled popular
//! lists) ports here as a pure module. The registry-metadata / HTTP and
//! git-walking detectors land as their consumers do.

pub mod typosquat;

pub use typosquat::{check_one, damerau_levenshtein, scan_deps, TyposquatFinding};
