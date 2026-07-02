//! GHA action-ref drift detector — Rust port of the pure core of
//! `packages/sca/supply_chain/gha_drift.py`.
//!
//! Flags `uses: owner/repo@<ref>` steps pinned to a mutable ref (tag or branch)
//! rather than a 40-char commit SHA. The filesystem walk (`scan_target`,
//! `_project_host_dep`) stays call-site in Python; [`scan_text`] takes a
//! workflow file's already-read content + its display path.

use std::sync::OnceLock;

use regex::Regex;

/// One mutable-ref `uses:` occurrence (the pure part of `GhaDriftFinding`).
#[derive(Clone, Debug, PartialEq)]
pub struct GhaDriftMatch {
    pub action: String,
    pub ref_: String,
    pub ref_kind: String,
    pub line: usize,
    pub severity: String,
    pub detail: String,
    pub confidence_reason: String,
}

fn uses_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^\s*-?\s*uses\s*:\s*(?P<spec>[A-Za-z0-9_./-]+@[A-Za-z0-9_./-]+)\s*(?:#.*)?$")
            .unwrap()
    })
}

fn sha_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-f0-9]{40}$").unwrap())
}

fn semverish_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^v?\d").unwrap())
}

/// Categorise a `uses: owner/repo@<ref>` ref (`_classify_ref`):
/// `sha` / `tag` / `branch_or_other`.
pub fn classify_ref(ref_: &str) -> &'static str {
    if sha_re().is_match(&ref_.to_lowercase()) {
        return "sha";
    }
    if semverish_re().is_match(ref_) && !ref_.contains('/') {
        return "tag";
    }
    "branch_or_other"
}

/// Scan a workflow file's already-read `text` for mutable-ref `uses:` steps
/// (the pure body of `_scan_text`). `rel` is the display path.
pub fn scan_text(text: &str, rel: &str) -> Vec<GhaDriftMatch> {
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let Some(caps) = uses_re().captures(line) else { continue };
        let spec = caps.name("spec").unwrap().as_str();
        if spec.starts_with("./") || spec.starts_with("../") || spec.starts_with("docker://") {
            continue;
        }
        let Some((action, ref_)) = spec.rsplit_once('@') else { continue };
        let ref_kind = classify_ref(ref_);
        if ref_kind == "sha" {
            continue;
        }
        let (severity, reason) = if ref_kind == "branch_or_other" {
            ("medium", "branch / non-tag ref \u{2014} every CI run picks up whatever the head commit is at that moment")
        } else {
            ("low", "tag ref \u{2014} the action's owner can re-publish the same tag pointing at different code")
        };
        let detail = format!(
            "`{rel}:{line_no}` uses `{action}@{ref_}` \u{2014} {reason}; pin to a 40-char commit SHA for supply-chain integrity"
        );
        out.push(GhaDriftMatch {
            action: action.to_string(),
            ref_: ref_.to_string(),
            ref_kind: ref_kind.to_string(),
            line: line_no,
            severity: severity.to_string(),
            detail,
            confidence_reason: format!("action ref is a {ref_kind}, not a commit SHA"),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify() {
        assert_eq!(classify_ref(&"a".repeat(40)), "sha");
        assert_eq!(classify_ref(&"A".repeat(40)), "sha"); // case-insensitive
        assert_eq!(classify_ref("v1"), "tag");
        assert_eq!(classify_ref("v1.2.3"), "tag");
        assert_eq!(classify_ref("1.0"), "tag");
        assert_eq!(classify_ref("v2beta"), "tag");
        assert_eq!(classify_ref("main"), "branch_or_other");
        assert_eq!(classify_ref("master"), "branch_or_other");
        assert_eq!(classify_ref("feature/x"), "branch_or_other");
        assert_eq!(classify_ref("release-1.0"), "branch_or_other");
        assert_eq!(classify_ref("dev"), "branch_or_other");
    }

    #[test]
    fn scan() {
        let txt = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/checkout@main\n      - uses: some/action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n      - uses: github/codeql-action/init@v3  # comment\n      - uses: ./local-action\n      - run: echo hi\n      - uses: owner/repo@feature/x\n";
        let got = scan_text(txt, ".github/workflows/ci.yml");
        assert_eq!(got.len(), 4);
        assert_eq!((got[0].action.as_str(), got[0].ref_.as_str(), got[0].ref_kind.as_str(), got[0].line, got[0].severity.as_str()),
            ("actions/checkout", "v4", "tag", 4, "low"));
        assert_eq!(got[0].detail, "`.github/workflows/ci.yml:4` uses `actions/checkout@v4` \u{2014} tag ref \u{2014} the action's owner can re-publish the same tag pointing at different code; pin to a 40-char commit SHA for supply-chain integrity");
        assert_eq!((got[1].ref_.as_str(), got[1].ref_kind.as_str(), got[1].line, got[1].severity.as_str()), ("main", "branch_or_other", 5, "medium"));
        // SHA-pinned (line 6) is skipped; sub-action path preserved (line 7).
        assert_eq!((got[2].action.as_str(), got[2].ref_.as_str(), got[2].line), ("github/codeql-action/init", "v3", 7));
        assert_eq!((got[3].action.as_str(), got[3].ref_.as_str(), got[3].line), ("owner/repo", "feature/x", 10));
        assert_eq!(got[1].confidence_reason, "action ref is a branch_or_other, not a commit SHA");
    }
}
