//! Dockerfile parsing — Rust port of the pure surface of `core/dockerfile/`.
//! The `apt` package extractor's shlex-driven top level + the `Instruction`
//! parser stay Python; the self-contained line/token helpers port here.

pub mod apt;

pub use apt::{
    flatten_run, inline_comment_start, is_clean_var_substitution, is_env_prefix, parse_pkg,
    strip_subshell_paren, AptPackage,
};
