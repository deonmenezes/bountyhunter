//! Software-composition-analysis (SCA) dependency model + manifest parsers —
//! Rust port of `packages/sca/models.py` (the Dependency core) and
//! `packages/sca/parsers/*`.
//!
//! The parsers are pure text/format transforms; file reading stays at the call
//! site (each parser takes already-read content + the declaring path). HTTP
//! registries, resolvers, and the LLM layers stay in Python.

pub mod cargo;
pub mod composer;
pub mod cmake_fetchcontent;
pub mod compose;
pub mod conan;
pub mod directory_packages_props;
pub mod gemfile;
pub mod gitlab_ci;
pub mod gitmodules;
pub mod gomod;
pub mod gradle_dsl;
pub mod gradle_lockfile;
pub mod gradle_version_catalog;
pub mod helm_chart;
pub mod kubernetes;
pub mod models;
pub mod nuget;
pub mod package_lock_json;
pub mod pipfile_lock;
pub mod ecosystems;
pub mod findings;
pub mod hygiene;
pub mod pnpm_lock;
pub mod pom;
pub mod poetry_lock;
pub mod precommit;
pub mod purl;
pub mod risk;
pub mod suppressions;
pub mod thresholds;
pub mod transitive_drop;
pub mod toml_util;
pub mod uv_lock;
pub mod vcpkg;
pub mod yarn_lock;

pub use findings::severity_rank;
pub use models::{Confidence, Dependency, PinStyle, Reachability};
