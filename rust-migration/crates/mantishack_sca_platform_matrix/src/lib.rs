//! Project platform-matrix discovery — Rust port of
//! `packages/sca/platform_matrix/`.
//!
//! `glibc_db` (distro/runner → libc lookup) ports here as a pure module. The
//! matrix data structures and the filesystem-walking `discover_platform_matrix`
//! (Dockerfile / devcontainer / bake / GHA-workflow scanners) are ported as
//! their consumers land; file reading stays call-site in Python for now.

pub mod glibc_db;
pub mod matrix;

pub use glibc_db::{known_distros, lookup_distro_libc, lookup_runner_libc, LibcVersion};
pub use matrix::{
    add_runner, canonical_arch, extract_gha_build_push_platforms, extract_platforms_from_text,
    from_image_to_distro, is_dockerfile, parse_macos_runner_version, walk_bake_hcl_text,
    walk_bake_json_text, walk_dockerfile_text, walk_gha_workflow_text, PlatformPair,
    ProjectPlatformMatrix,
};
