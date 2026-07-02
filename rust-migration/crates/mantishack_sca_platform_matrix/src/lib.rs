//! Project platform-matrix discovery — Rust port of
//! `packages/sca/platform_matrix/`.
//!
//! `glibc_db` (distro/runner → libc lookup) ports here as a pure module. The
//! matrix data structures and the filesystem-walking `discover_platform_matrix`
//! (Dockerfile / devcontainer / bake / GHA-workflow scanners) are ported as
//! their consumers land; file reading stays call-site in Python for now.

pub mod glibc_db;

pub use glibc_db::{known_distros, lookup_distro_libc, lookup_runner_libc, LibcVersion};
