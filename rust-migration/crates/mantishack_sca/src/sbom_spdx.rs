//! SPDX 2.3 SBOM helpers — Rust port of the self-contained functions in
//! `packages/sca/sbom_spdx.py`. The full document assembly + atomic write stay
//! Python; the SPDX license-value validator + stable SPDX-ID generator port here.

use std::collections::HashSet;

use crate::models::Dependency;

/// Validate a declared license fits SPDX expression grammar, else `NOASSERTION`
/// (`_spdx_license_value`). Rejects disallowed chars and English-prose tokens.
pub fn spdx_license_value(declared: &str) -> String {
    let text = declared.trim();
    if text.is_empty() {
        return "NOASSERTION".to_string();
    }
    // Only SPDX-shaped characters (ASCII alnum + `-+. ()` + space).
    if !text.chars().all(|c| c.is_ascii_alphanumeric() || "-+. ()".contains(c)) {
        return "NOASSERTION".to_string();
    }
    // Prose detector: reject an all-lowercase, all-alphabetic, non-keyword,
    // length>=3 token ("See the LICENSE file for details" -> NOASSERTION).
    for tok in text.split_whitespace() {
        let cased: Vec<char> = tok.chars().filter(|c| c.is_alphabetic()).collect();
        let islower = !cased.is_empty() && cased.iter().all(|c| c.is_lowercase());
        let isalpha = !tok.is_empty() && tok.chars().all(|c| c.is_alphabetic());
        let low = tok.to_lowercase();
        let is_keyword = matches!(low.as_str(), "and" | "or" | "with");
        if islower && isalpha && !is_keyword && tok.chars().count() >= 3 {
            return "NOASSERTION".to_string();
        }
    }
    text.to_string()
}

/// Stable `SPDXRef-<id>` for a dependency, deduplicated against `seen`
/// (`_spdx_id_for`). Non-conforming chars become `-`; collisions get a counter.
pub fn spdx_id_for(dep: &Dependency, seen: &mut HashSet<String>) -> String {
    let version = dep.version.as_deref().filter(|v| !v.is_empty()).unwrap_or("unknown");
    let base = format!("{}-{}-{}", dep.ecosystem, dep.name, version);
    let safe: String = base
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '-' })
        .collect();
    let spdx_id = format!("SPDXRef-{safe}");
    if seen.insert(spdx_id.clone()) {
        return spdx_id;
    }
    // Collision (same dep across manifests) — append the first free counter.
    let mut n = 2;
    loop {
        let candidate = format!("{spdx_id}-{n}");
        if seen.insert(candidate.clone()) {
            return candidate;
        }
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, PinStyle};

    #[test]
    fn license_values() {
        assert_eq!(spdx_license_value("MIT"), "MIT");
        assert_eq!(spdx_license_value("MIT OR Apache-2.0"), "MIT OR Apache-2.0");
        assert_eq!(spdx_license_value(""), "NOASSERTION");
        assert_eq!(spdx_license_value("See the LICENSE file"), "NOASSERTION");
        assert_eq!(spdx_license_value("mit"), "NOASSERTION"); // lowercase prose token
        assert_eq!(spdx_license_value("Apache-2.0"), "Apache-2.0");
        assert_eq!(spdx_license_value("GPL-2.0 WITH Classpath-exception-2.0"), "GPL-2.0 WITH Classpath-exception-2.0");
        assert_eq!(spdx_license_value("http://example.com/license"), "NOASSERTION"); // disallowed chars
        assert_eq!(spdx_license_value("Custom OR MIT"), "Custom OR MIT");
    }

    fn dep(eco: &str, name: &str, ver: Option<&str>) -> Dependency {
        Dependency {
            ecosystem: eco.into(), name: name.into(), version: ver.map(str::to_string),
            declared_in: "p".into(), scope: "main".into(), is_lockfile: false,
            pin_style: PinStyle::Exact, direct: true, purl: "p".into(),
            parser_confidence: Confidence::new("high", ""), declared_license: None,
            commented_out: false, source_kind: "manifest".into(), source_extra: None,
        }
    }

    #[test]
    fn spdx_ids_and_collisions() {
        let mut seen = HashSet::new();
        assert_eq!(spdx_id_for(&dep("npm", "@types/node", Some("1.0")), &mut seen), "SPDXRef-npm--types-node-1.0");
        assert_eq!(spdx_id_for(&dep("PyPI", "flask", Some("2.0.0")), &mut seen), "SPDXRef-PyPI-flask-2.0.0");
        // Same dep (no version) three times -> counter suffixes.
        assert_eq!(spdx_id_for(&dep("npm", "lodash", None), &mut seen), "SPDXRef-npm-lodash-unknown");
        assert_eq!(spdx_id_for(&dep("npm", "lodash", None), &mut seen), "SPDXRef-npm-lodash-unknown-2");
        assert_eq!(spdx_id_for(&dep("npm", "lodash", None), &mut seen), "SPDXRef-npm-lodash-unknown-3");
    }
}
