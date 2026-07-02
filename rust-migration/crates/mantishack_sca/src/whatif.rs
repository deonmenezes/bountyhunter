//! Upgrade-impact ("what-if") pure helpers — Rust port of the self-contained
//! functions in `packages/sca/whatif.py`. The OSV/KEV/EPSS re-query + report
//! rendering stay Python; the modal-spec parser + target synthesiser port here.

use crate::models::{Confidence, Dependency, PinStyle};

/// Parse `ECO:NAME@VERSION` (when `expect_version`) or `ECO:NAME`
/// (`_parse_modal_spec`). Returns `(eco, name, version)` (version empty when not
/// expected), or `None` if malformed.
pub fn parse_modal_spec(raw: &str, expect_version: bool) -> Option<(String, String, String)> {
    let (eco, rest) = raw.split_once(':')?;
    let eco = eco.trim();
    if eco.is_empty() {
        return None;
    }
    if expect_version {
        let (name, version) = rest.rsplit_once('@')?;
        // Truthiness check is pre-strip (Python `if not (name and version)`).
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some((eco.to_string(), name.trim().to_string(), version.trim().to_string()))
    } else {
        Some((eco.to_string(), rest.trim().to_string(), String::new()))
    }
}

/// Synthesise an operator-supplied "what-if" upgrade target Dependency
/// (`_synthesise`).
pub fn synthesise(ecosystem: &str, name: &str, version: &str) -> Dependency {
    Dependency {
        ecosystem: ecosystem.to_string(),
        name: name.to_string(),
        version: Some(version.to_string()),
        declared_in: format!("<mantishack-sca upgrade: {ecosystem}:{name}@{version}>"),
        scope: "main".to_string(),
        is_lockfile: false,
        pin_style: PinStyle::Exact,
        direct: true,
        purl: format!("pkg:{}/{name}@{version}", ecosystem.to_lowercase()),
        parser_confidence: Confidence::new("high", "operator-supplied whatif target"),
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
        source_extra: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(raw: &str, expect: bool) -> Option<(String, String, String)> {
        parse_modal_spec(raw, expect)
    }

    #[test]
    fn modal_specs() {
        assert_eq!(spec("npm:lodash@4.17.21", true), Some(("npm".into(), "lodash".into(), "4.17.21".into())));
        assert_eq!(spec("npm:@types/node@20.0.0", true), Some(("npm".into(), "@types/node".into(), "20.0.0".into())));
        assert_eq!(spec("npm:lodash", false), Some(("npm".into(), "lodash".into(), "".into())));
        assert_eq!(spec("lodash", true), None); // no colon
        assert_eq!(spec(":lodash@1.0", true), None); // empty eco
        assert_eq!(spec("npm:lodash", true), None); // no @
        assert_eq!(spec("npm:@1.0", true), None); // empty name before @
        assert_eq!(spec(" npm : lodash @ 1.0 ", true), Some(("npm".into(), "lodash".into(), "1.0".into())));
    }

    #[test]
    fn synth_target() {
        let d = synthesise("npm", "lodash", "4.17.21");
        assert_eq!(d.ecosystem, "npm");
        assert_eq!(d.version.as_deref(), Some("4.17.21"));
        assert_eq!(d.declared_in, "<mantishack-sca upgrade: npm:lodash@4.17.21>");
        assert_eq!(d.purl, "pkg:npm/lodash@4.17.21");
        assert_eq!(d.pin_style, PinStyle::Exact);
        assert!(d.direct);
        assert_eq!(d.parser_confidence.reason, "operator-supplied whatif target");
        // Ecosystem is lowercased only in the purl.
        assert_eq!(synthesise("PyPI", "flask", "2.0").purl, "pkg:pypi/flask@2.0");
    }
}
