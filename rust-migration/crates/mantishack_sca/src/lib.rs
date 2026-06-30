//! Software-composition-analysis (SCA) dependency model + manifest parsers —
//! Rust port of `packages/sca/models.py` (the Dependency core) and
//! `packages/sca/parsers/*`.
//!
//! The parsers are pure text/format transforms; file reading stays at the call
//! site (each parser takes already-read content + the declaring path). HTTP
//! registries, resolvers, and the LLM layers stay in Python.

pub mod composer;
pub mod gemfile;
pub mod gomod;
pub mod models;

pub use models::{Confidence, Dependency, PinStyle};
