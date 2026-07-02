//! Wheel platform-tag parsing + compatibility check — Rust port of
//! `packages/sca/wheel_compat/`.
//!
//! `wheel_tags` (PEP 425 filename → platform tags) ports here as a pure module.
//! `compat.py` (matrix ↔ wheel-tag verdicts) and `scan.py` (finding synthesis)
//! land as their consumers do; the PyPI wheel-list fetch stays call-site.

pub mod compat;
pub mod wheel_tags;

pub use compat::{
    best_match, build_wheel_matrix, check_compat, is_stable_version, verdict_for_pair,
    version_key, CompatVerdict, WheelMatrix,
};
pub use wheel_tags::{parse_single_platform_tag, parse_wheel_filename, WheelTag};
