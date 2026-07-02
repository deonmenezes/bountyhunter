//! LLM-analysis helpers — Rust port of the pure surface of
//! `packages/llm_analysis/`. The LLM describe/judge tiebreak stays Python; the
//! intent-match heuristics + verdict logic port here.

pub mod intent_match;

pub use intent_match::{
    compile_error_anchor, count_signals, cwe_shape, file_overlap, function_overlap, initial_verdict,
    Signal, VERDICT_MATCHES, VERDICT_OFF_TARGET, VERDICT_UNCERTAIN,
};
