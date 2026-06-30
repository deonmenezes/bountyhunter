//! Software-composition-analysis (SCA) dependency model + manifest parsers —
//! Rust port of `packages/sca/models.py` (the Dependency core) and
//! `packages/sca/parsers/*`.
//!
//! The parsers are pure text/format transforms; file reading stays at the call
//! site (each parser takes already-read content + the declaring path). HTTP
//! registries, resolvers, and the LLM layers stay in Python.

pub mod cargo;
pub mod composer;
pub mod conan;
pub mod gemfile;
pub mod gitmodules;
pub mod gomod;
pub mod gradle_lockfile;
pub mod models;
pub mod package_lock_json;
pub mod pipfile_lock;
pub mod pnpm_lock;
pub mod poetry_lock;
pub mod toml_util;
pub mod uv_lock;
pub mod vcpkg;
pub mod yarn_lock;

pub use models::{Confidence, Dependency, PinStyle};
