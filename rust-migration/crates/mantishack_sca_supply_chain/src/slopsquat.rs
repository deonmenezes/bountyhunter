//! Slopsquat (LLM-hallucinated package-name) detector — Rust port of
//! `packages/sca/supply_chain/slopsquat.py`. Pure; reuses the embedded popular
//! lists from [`crate::typosquat`].

use std::collections::HashSet;
use std::sync::OnceLock;

use mantishack_sca::{Confidence, Dependency};

use crate::typosquat::popular_for;

/// One slopsquat-candidate hit (`SlopsquatFinding`).
#[derive(Clone, Debug, PartialEq)]
pub struct SlopsquatFinding {
    pub dependency: Dependency,
    pub score: f64,
    pub reasons: Vec<String>,
    pub suspected_root: Option<String>,
    pub severity: String,
    pub confidence: Confidence,
}

fn generic_words() -> &'static HashSet<&'static str> {
    static W: OnceLock<HashSet<&'static str>> = OnceLock::new();
    W.get_or_init(|| {
        [
            "pro", "utils", "util", "helper", "helpers", "core", "cli", "tool", "tools",
            "toolkit", "kit", "extra", "extras", "extended", "plus", "next", "new", "modern",
            "improved", "master", "client", "api", "lib", "library", "module", "package",
            "wrapper", "framework",
        ]
        .into_iter()
        .collect()
    })
}

fn language_suffixes(eco: &str) -> &'static [&'static str] {
    match eco {
        "npm" => &["py", "python", "rust", "go", "rb", "ruby"],
        "PyPI" => &["js", "ts", "node", "rust", "go", "rb"],
        "Cargo" => &["js", "ts", "py", "python", "rb"],
        "RubyGems" => &["js", "ts", "py", "python", "rs"],
        "Maven" => &["js", "py", "rb", "rs"],
        "Packagist" => &["js", "py", "rb", "rs"],
        _ => &[],
    }
}

fn trusted_npm_scopes() -> &'static HashSet<&'static str> {
    static S: OnceLock<HashSet<&'static str>> = OnceLock::new();
    S.get_or_init(|| {
        [
            "@types", "@typescript-eslint", "@aws-sdk", "@aws-cdk", "@azure", "@google-cloud",
            "@anthropic-ai", "@openai", "@huggingface", "@angular", "@vue", "@nuxt", "@nestjs",
            "@nx", "@babel", "@swc", "@vitejs", "@vitest", "@radix-ui", "@tanstack", "@trpc",
            "@tailwindcss", "@mui", "@chakra-ui", "@react-native", "@expo", "@stripe", "@supabase",
            "@vercel", "@cloudflare", "@playwright", "@storybook", "@grafana", "@redhat",
            "@microsoft", "@fluentui", "@eslint", "@prettier", "@parcel", "@rollup", "@docusaurus",
            "@octokit", "@graphql-tools",
        ]
        .into_iter()
        .collect()
    })
}

fn score_weight(reason: &str) -> f64 {
    match reason {
        "lookalike_collapse_match" => 0.7,
        "popular_prefix_generic_suffix" => 0.6,
        "popular_prefix_language_suffix" => 0.4,
        "untrusted_scope" => 0.2,
        _ => 0.0,
    }
}

/// Run the heuristic on every direct dep (`scan_deps`).
pub fn scan_deps(deps: &[Dependency]) -> Vec<SlopsquatFinding> {
    deps.iter().filter(|d| d.direct).filter_map(check_dep).collect()
}

/// Run the slopsquat heuristic against a single dependency (`check_dep`).
pub fn check_dep(dep: &Dependency) -> Option<SlopsquatFinding> {
    let name = dep.name.to_lowercase();
    let eco = dep.ecosystem.as_str();
    let popular = popular_for(eco)?;
    if popular.list.is_empty() {
        return None;
    }
    if popular.set.contains(&name) {
        return None; // legit popular dep
    }

    let mut reasons: Vec<String> = Vec::new();
    let mut suspected_root: Option<String> = None;

    // 1. Lookalike-character collapse against popular names.
    let collapsed = collapse_lookalikes(&name);
    if collapsed != name {
        for pop in &popular.list {
            if collapse_lookalikes(pop) == collapsed {
                reasons.push("lookalike_collapse_match".to_string());
                suspected_root = Some(pop.clone());
                break;
            }
        }
    }

    let (prefix, suffix) = split_suffix(&name);
    // 2. Generic suffix on a popular prefix.
    if let (Some(prefix), Some(suffix)) = (&prefix, &suffix) {
        if popular.set.contains(prefix) && generic_words().contains(suffix.as_str()) {
            reasons.push("popular_prefix_generic_suffix".to_string());
            if suspected_root.is_none() {
                suspected_root = Some(prefix.clone());
            }
        }
    }
    // 3. Language-suffix on a popular prefix.
    if let (Some(prefix), Some(suffix)) = (&prefix, &suffix) {
        if popular.set.contains(prefix) && language_suffixes(eco).contains(&suffix.as_str()) {
            reasons.push("popular_prefix_language_suffix".to_string());
            if suspected_root.is_none() {
                suspected_root = Some(prefix.clone());
            }
        }
    }
    // 4. Untrusted scope (npm only) — weak contributor, never flags alone.
    if eco == "npm" && name.starts_with('@') && name.contains('/') {
        let scope = name.split_once('/').map(|(s, _)| s).unwrap_or(&name);
        if !trusted_npm_scopes().contains(scope) {
            reasons.push("untrusted_scope".to_string());
        }
    }

    if reasons.is_empty() {
        return None;
    }
    let score = 1.0_f64.min(reasons.iter().map(|r| score_weight(r)).sum());
    let severity = severity(score)?;
    let confidence = confidence(&reasons, score);
    Some(SlopsquatFinding {
        dependency: dep.clone(),
        score,
        reasons,
        suspected_root,
        severity: severity.to_string(),
        confidence,
    })
}

/// Map confusable characters to canonical forms (`_collapse_lookalikes`):
/// `{l, I, 1}` → `i`; `{0, O}` → `o`.
fn collapse_lookalikes(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'l' | 'I' | '1' => 'i',
            '0' | 'O' => 'o',
            other => other,
        })
        .collect()
}

/// Split `<prefix>-<suffix>` / `<prefix>_<suffix>` on the LAST separator
/// (`_split_suffix`); `(None, None)` when there is no interior separator.
fn split_suffix(name: &str) -> (Option<String>, Option<String>) {
    let work = if name.starts_with('@') && name.contains('/') {
        name.split_once('/').map(|(_, rest)| rest).unwrap_or(name)
    } else {
        name
    };
    let dash = work.rfind('-').map(|i| i as i64).unwrap_or(-1);
    let under = work.rfind('_').map(|i| i as i64).unwrap_or(-1);
    let sep_idx = dash.max(under);
    if sep_idx <= 0 || sep_idx >= work.len() as i64 - 1 {
        return (None, None);
    }
    let sep_idx = sep_idx as usize;
    (Some(work[..sep_idx].to_string()), Some(work[sep_idx + 1..].to_string()))
}

fn severity(score: f64) -> Option<&'static str> {
    if score >= 0.7 {
        Some("high")
    } else if score >= 0.5 {
        Some("medium")
    } else if score >= 0.3 {
        Some("low")
    } else {
        None
    }
}

fn confidence(reasons: &[String], score: f64) -> Confidence {
    if reasons.len() >= 2 {
        Confidence::new(
            "medium",
            &format!("multiple slopsquat-shaped signals (score {:.2}): {}", score, reasons.join(", ")),
        )
    } else {
        Confidence::new("low", &format!("single slopsquat signal (score {:.2}): {}", score, reasons[0]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantishack_sca::PinStyle;

    fn dep(name: &str, eco: &str) -> Dependency {
        Dependency {
            ecosystem: eco.to_string(),
            name: name.to_string(),
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

    #[test]
    fn helpers() {
        assert_eq!(collapse_lookalikes("lodash"), "iodash");
        assert_eq!(collapse_lookalikes("1odash"), "iodash");
        assert_eq!(collapse_lookalikes("g00gle"), "googie");
        assert_eq!(split_suffix("aws-sdk-helpers"), (Some("aws-sdk".into()), Some("helpers".into())));
        assert_eq!(split_suffix("nodash"), (None, None));
        assert_eq!(split_suffix("@scope/foo-bar"), (Some("foo".into()), Some("bar".into())));
        assert_eq!(split_suffix("a-"), (None, None));
        assert_eq!(split_suffix("-a"), (None, None));
        assert_eq!(severity(0.5), Some("medium"));
        assert_eq!(severity(0.2), None);
    }

    #[test]
    fn findings() {
        assert!(check_dep(&dep("lodash", "npm")).is_none()); // exact popular

        let f = check_dep(&dep("1odash", "npm")).unwrap();
        assert_eq!((f.score, f.reasons.as_slice(), f.suspected_root.as_deref(), f.severity.as_str()),
            (0.7, ["lookalike_collapse_match".to_string()].as_slice(), Some("lodash"), "high"));
        assert_eq!(f.confidence.reason, "single slopsquat signal (score 0.70): lookalike_collapse_match");

        let f = check_dep(&dep("lodash-pro", "npm")).unwrap();
        assert_eq!((f.score, f.reasons[0].as_str(), f.severity.as_str()), (0.6, "popular_prefix_generic_suffix", "medium"));

        let f = check_dep(&dep("lodash-py", "npm")).unwrap();
        assert_eq!((f.score, f.reasons[0].as_str(), f.severity.as_str()), (0.4, "popular_prefix_language_suffix", "low"));

        // Untrusted scope alone stays below the info floor -> no finding.
        assert!(check_dep(&dep("@evil/foo", "npm")).is_none());

        let f = check_dep(&dep("@evil/lodash-pro", "npm")).unwrap();
        assert_eq!(f.reasons, vec!["popular_prefix_generic_suffix", "untrusted_scope"]);
        assert_eq!((f.score, f.severity.as_str(), f.confidence.level.as_str()), (0.8, "high", "medium"));
        assert_eq!(f.confidence.reason, "multiple slopsquat-shaped signals (score 0.80): popular_prefix_generic_suffix, untrusted_scope");

        assert!(check_dep(&dep("totallyunrelatedxyz", "npm")).is_none());
        assert_eq!(check_dep(&dep("requests-js", "PyPI")).unwrap().suspected_root.as_deref(), Some("requests"));
    }
}
