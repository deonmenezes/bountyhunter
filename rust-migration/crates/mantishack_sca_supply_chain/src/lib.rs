//! Supply-chain heuristics — Rust port of `packages/sca/supply_chain/`.
//!
//! `typosquat` (Damerau-Levenshtein candidate detection over bundled popular
//! lists) ports here as a pure module. The registry-metadata / HTTP and
//! git-walking detectors land as their consumers do.

pub mod artefacts;
pub mod exfil_destinations;
pub mod install_hooks;
pub mod sentinel;
pub mod slopsquat;
pub mod typosquat;
pub mod typosquat_domain;

pub use artefacts::{
    check_disguised_filename_head, check_obfuscated_content, classify_binary_payload,
    shannon_entropy,
};
pub use exfil_destinations::{is_non_routable_ipv4, scan_content, ExfilMatch};
pub use install_hooks::{scan_scripts, InstallHookFinding, InstallHookHit};
pub use sentinel::{scan_deps as scan_deps_sentinel, SentinelHit};
pub use slopsquat::{check_dep, scan_deps as scan_deps_slopsquat, SlopsquatFinding};
pub use typosquat::{check_one, damerau_levenshtein, scan_deps, TyposquatFinding};
pub use typosquat_domain::{find_suspect_hosts, hosts_in, nearest_popular, SuspectHost};
