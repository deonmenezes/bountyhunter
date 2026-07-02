//! GitHub Actions `uses: <owner>/<repo>@<ref>` in-place rewriter — Rust port of
//! the pure core of `packages/sca/rewriters/gha_uses.py`. Content in, content
//! out; the atomic file write stays call-site in Python.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::{py_repr, RewriteEdit, RewriteResult};

/// Apply `uses:` ref-bump edits to GHA workflow `text` (pure body of
/// `rewrite_gha_uses`; fs read/atomic-write stays in Python).
pub fn rewrite_gha_uses_text(text: &str, edits: &[RewriteEdit]) -> (String, Vec<RewriteResult>) {
    let mut new_text = text.to_string();
    let mut results = Vec::with_capacity(edits.len());
    for edit in edits {
        let (t, r) = apply_one_uses(&new_text, edit);
        new_text = t;
        results.push(r);
    }
    (new_text, results)
}

fn sha_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-f0-9]{40}$").unwrap())
}

fn looks_like_sha(ref_: &str) -> bool {
    sha_re().is_match(ref_)
}

fn apply_one_uses(text: &str, edit: &RewriteEdit) -> (String, RewriteResult) {
    // extra["old_sha"] present + truthy → SHA-pinned-with-comment path.
    let old_sha = edit
        .extra
        .as_ref()
        .and_then(|e| e.get("old_sha"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    if old_sha.is_some() {
        return apply_sha_pinned(text, edit);
    }

    let locator = regex::escape(&edit.locator);
    let pattern = Regex::new(&format!(
        r"(?m)^(\s*(?:-\s+)?uses:\s*{locator}(?:/[\w./-]+)?@)([^\s#]+)(\s|$|#)"
    ))
    .unwrap();
    let Some(caps) = pattern.captures(text) else {
        return (text.to_string(), RewriteResult::new(edit.clone(), false, "not_found"));
    };
    let g2 = caps.get(2).unwrap();
    let current_ref = g2.as_str();
    if looks_like_sha(current_ref) {
        let reason = format!(
            "value_mismatch: file uses SHA-pinned ref {}..., bumper only handles tag-pinned refs in Phase 3.b",
            &current_ref[..12]
        );
        return (text.to_string(), RewriteResult::new(edit.clone(), false, &reason));
    }
    if current_ref == edit.new_value {
        return (text.to_string(), RewriteResult::new(edit.clone(), false, "no_change"));
    }
    if current_ref != edit.old_value {
        let reason = format!(
            "value_mismatch: file has {}, plan expected {}",
            py_repr(current_ref),
            py_repr(&edit.old_value),
        );
        return (text.to_string(), RewriteResult::new(edit.clone(), false, &reason));
    }
    let mut new_text = String::with_capacity(text.len());
    new_text.push_str(&text[..g2.start()]);
    new_text.push_str(&edit.new_value);
    new_text.push_str(&text[g2.end()..]);
    (new_text, RewriteResult::new(edit.clone(), true, "applied"))
}

fn apply_sha_pinned(text: &str, edit: &RewriteEdit) -> (String, RewriteResult) {
    let extra = edit.extra.as_ref();
    let old_sha = extra.and_then(|e| e.get("old_sha")).and_then(Value::as_str).unwrap_or("");
    let new_sha = extra.and_then(|e| e.get("new_sha")).and_then(Value::as_str).unwrap_or("");
    let locator = regex::escape(&edit.locator);
    let pattern = Regex::new(&format!(
        r"(?m)^(\s*(?:-\s+)?uses:\s*{locator}(?:/[\w./-]+)?@)([a-f0-9]{{40}})(\s+#\s*was\s+)([^\s#]+)([\s#]|$)"
    ))
    .unwrap();
    let Some(caps) = pattern.captures(text) else {
        return (text.to_string(), RewriteResult::new(edit.clone(), false, "not_found"));
    };
    let g2 = caps.get(2).unwrap();
    let g4 = caps.get(4).unwrap();
    let file_sha = g2.as_str();
    let file_tag = g4.as_str();
    if file_sha == new_sha && file_tag == edit.new_value {
        return (text.to_string(), RewriteResult::new(edit.clone(), false, "no_change"));
    }
    if file_sha != old_sha {
        let reason = format!(
            "value_mismatch: file SHA {}... differs from plan's old SHA {}...",
            &file_sha[..12],
            &old_sha[..old_sha.len().min(12)]
        );
        return (text.to_string(), RewriteResult::new(edit.clone(), false, &reason));
    }
    if file_tag != edit.old_value {
        let reason = format!(
            "value_mismatch: file '# was {}' differs from plan's old tag {}",
            file_tag,
            py_repr(&edit.old_value),
        );
        return (text.to_string(), RewriteResult::new(edit.clone(), false, &reason));
    }
    // Rewrite both the SHA (group 2) and the tag in the comment (group 4).
    let mut new_text = String::with_capacity(text.len());
    new_text.push_str(&text[..g2.start()]);
    new_text.push_str(new_sha);
    new_text.push_str(&text[g2.end()..g4.start()]);
    new_text.push_str(&edit.new_value);
    new_text.push_str(&text[g4.end()..]);
    (new_text, RewriteResult::new(edit.clone(), true, "applied"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn one(text: &str, loc: &str, old: &str, new: &str) -> (String, bool, String) {
        let (t, r) = apply_one_uses(text, &RewriteEdit::new(loc, old, new));
        (t, r.applied, r.reason)
    }
    fn one_sha(text: &str, loc: &str, old: &str, new: &str, old_sha: &str, new_sha: &str) -> (String, bool, String) {
        let mut e = RewriteEdit::new(loc, old, new);
        e.extra = Some(json!({"old_sha": old_sha, "new_sha": new_sha}));
        let (t, r) = apply_one_uses(text, &e);
        (t, r.applied, r.reason)
    }

    #[test]
    fn tag_pinned_cases() {
        assert_eq!(one("      - uses: actions/checkout@v4\n", "actions/checkout", "v4", "v5"),
            ("      - uses: actions/checkout@v5\n".into(), true, "applied".into()));
        assert_eq!(one("    uses: actions/checkout@v4\n", "actions/checkout", "v4", "v5"),
            ("    uses: actions/checkout@v5\n".into(), true, "applied".into()));
        assert_eq!(one("      - uses: github/codeql-action/init@v3\n", "github/codeql-action", "v3", "v4"),
            ("      - uses: github/codeql-action/init@v4\n".into(), true, "applied".into()));
        assert_eq!(one("      - uses: actions/checkout@v5\n", "actions/checkout", "v4", "v5"),
            ("      - uses: actions/checkout@v5\n".into(), false, "no_change".into()));
        assert_eq!(one("      - uses: actions/checkout@v2\n", "actions/checkout", "v4", "v5"),
            ("      - uses: actions/checkout@v2\n".into(), false, "value_mismatch: file has 'v2', plan expected 'v4'".into()));
        assert_eq!(one("      - uses: other/thing@v1\n", "actions/checkout", "v4", "v5"),
            ("      - uses: other/thing@v1\n".into(), false, "not_found".into()));
        assert_eq!(one("      - uses: actions/checkout@v4 # pin\n", "actions/checkout", "v4", "v5"),
            ("      - uses: actions/checkout@v5 # pin\n".into(), true, "applied".into()));
    }

    #[test]
    fn sha_ref_refused_in_tag_path() {
        let sha = "a".repeat(40);
        let (_, applied, reason) = one(&format!("      - uses: actions/checkout@{sha}\n"), "actions/checkout", "v4", "v5");
        assert!(!applied);
        assert_eq!(reason, "value_mismatch: file uses SHA-pinned ref aaaaaaaaaaaa..., bumper only handles tag-pinned refs in Phase 3.b");
    }

    #[test]
    fn sha_pinned_cases() {
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let c = "c".repeat(40);
        assert_eq!(one_sha(&format!("      - uses: actions/checkout@{a}  # was v4\n"), "actions/checkout", "v4", "v5", &a, &b),
            (format!("      - uses: actions/checkout@{b}  # was v5\n"), true, "applied".into()));
        assert_eq!(one_sha(&format!("      - uses: actions/checkout@{b}  # was v5\n"), "actions/checkout", "v4", "v5", &a, &b),
            (format!("      - uses: actions/checkout@{b}  # was v5\n"), false, "no_change".into()));
        assert_eq!(one_sha(&format!("      - uses: actions/checkout@{c}  # was v4\n"), "actions/checkout", "v4", "v5", &a, &b),
            (format!("      - uses: actions/checkout@{c}  # was v4\n"), false,
             "value_mismatch: file SHA cccccccccccc... differs from plan's old SHA aaaaaaaaaaaa...".into()));
        assert_eq!(one_sha(&format!("      - uses: actions/checkout@{a}  # was v3\n"), "actions/checkout", "v4", "v5", &a, &b),
            (format!("      - uses: actions/checkout@{a}  # was v3\n"), false,
             "value_mismatch: file '# was v3' differs from plan's old tag 'v4'".into()));
    }
}
