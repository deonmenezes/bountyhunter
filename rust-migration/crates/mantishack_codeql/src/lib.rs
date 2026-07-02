//! CodeQL dataflow-validation support — Rust port of the pure surface of
//! `packages/codeql/dataflow_validator.py`. The `DataflowValidator` itself
//! (LLM + Z3 SMT) stays Python; the data models, the overflow-rule detector, and
//! the bitvector-profile inference port here.

pub mod dataflow_validator;

pub use dataflow_validator::{
    infer_bv_profile, is_overflow_rule, BVProfile, DataflowPath, DataflowStep, DataflowValidation,
    SMT_INFEASIBLE_CONFIDENCE,
};
