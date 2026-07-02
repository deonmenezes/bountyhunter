//! Supply-chain heuristics — Rust port of `packages/sca/supply_chain/`.
//!
//! `typosquat` (Damerau-Levenshtein candidate detection over bundled popular
//! lists) ports here as a pure module. The registry-metadata / HTTP and
//! git-walking detectors land as their consumers do.

use mantishack_sca::{Confidence, Dependency};
use serde_json::Value;

pub mod artefacts;
pub mod exfil_destinations;
pub mod gha_drift;
pub mod gha_freshness;
pub mod gha_sunset;
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
pub use gha_drift::{classify_ref, scan_text as gha_drift_scan_text, GhaDriftMatch};
pub use gha_freshness::{evaluate_dep as gha_freshness_evaluate, extract_major};
pub use gha_sunset::scan_dependencies as gha_sunset_scan;
pub use install_hooks::{scan_scripts, InstallHookFinding, InstallHookHit};

/// Supply-chain heuristic finding (`SupplyChainFinding`). `related_findings`,
/// `suppressed`, and `suppression_reason` carry the dataclass defaults.
#[derive(Clone, Debug, PartialEq)]
pub struct SupplyChainFinding {
    pub finding_id: String,
    pub kind: String,
    pub dependency: Dependency,
    pub detail: String,
    pub evidence: Value,
    pub severity: String,
    pub confidence: Confidence,
    pub related_findings: Vec<String>,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
}
pub use sentinel::{scan_deps as scan_deps_sentinel, SentinelHit};
pub use slopsquat::{check_dep, scan_deps as scan_deps_slopsquat, SlopsquatFinding};
pub use typosquat::{check_one, damerau_levenshtein, scan_deps, TyposquatFinding};
pub use typosquat_domain::{find_suspect_hosts, hosts_in, nearest_popular, SuspectHost};
