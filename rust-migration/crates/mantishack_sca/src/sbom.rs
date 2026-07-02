//! SBOM (CycloneDX) helpers — Rust port of the self-contained license functions
//! in `packages/sca/sbom.py`. The full BOM/VEX assembly + atomic write stay
//! Python; the SPDX-id heuristic + CycloneDX license-block shaping port here.

use serde_json::{json, Value};

const SPDX_LIKE: &[&str] = &[
    "MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "GPL-2.0", "GPL-3.0", "LGPL-2.1",
    "LGPL-3.0", "MPL-2.0", "AGPL-3.0", "EPL-1.0", "EPL-2.0", "Unlicense", "CC0-1.0", "WTFPL",
    "BSL-1.0", "0BSD",
];

/// Heuristic: does `text` look like an SPDX license id (`_looks_like_spdx_id`)?
/// Short, space-free, only alphanumerics / `.` / `-` / `+`.
pub fn looks_like_spdx_id(text: &str) -> bool {
    if SPDX_LIKE.contains(&text) {
        return true;
    }
    if text.contains(' ') {
        return false;
    }
    text.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '+')
}

/// Wrap a license string in CycloneDX's list-of-licenses shape (`_license_block`).
/// An SPDX expression (contains `OR`/`AND`/parens) → `expression`; a single id →
/// `license.id`; otherwise `license.name`.
pub fn license_block(spdx_or_name: &str) -> Value {
    let text = spdx_or_name.trim();
    if text.contains(" OR ") || text.contains(" AND ") || text.contains('(') || text.contains(')') {
        json!([{"expression": text}])
    } else if looks_like_spdx_id(text) {
        json!([{"license": {"id": text}}])
    } else {
        json!([{"license": {"name": text}}])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spdx_id_heuristic() {
        assert!(looks_like_spdx_id("MIT"));
        assert!(looks_like_spdx_id("Apache-2.0"));
        assert!(looks_like_spdx_id("")); // vacuous
        assert!(!looks_like_spdx_id("my license"));
        assert!(!looks_like_spdx_id("foo_bar")); // underscore
        assert!(!looks_like_spdx_id("x/y"));
    }

    #[test]
    fn license_blocks() {
        assert_eq!(license_block("MIT"), json!([{"license": {"id": "MIT"}}]));
        assert_eq!(license_block("Apache-2.0"), json!([{"license": {"id": "Apache-2.0"}}]));
        assert_eq!(license_block("MIT OR Apache-2.0"), json!([{"expression": "MIT OR Apache-2.0"}]));
        assert_eq!(license_block("(MIT OR ISC)"), json!([{"expression": "(MIT OR ISC)"}]));
        assert_eq!(license_block("GPL-2.0 AND MIT"), json!([{"expression": "GPL-2.0 AND MIT"}]));
        assert_eq!(license_block("Some Proprietary License"), json!([{"license": {"name": "Some Proprietary License"}}]));
        assert_eq!(license_block("  MIT  "), json!([{"license": {"id": "MIT"}}])); // trimmed
        assert_eq!(license_block("custom.thing-1+"), json!([{"license": {"id": "custom.thing-1+"}}]));
    }
}
