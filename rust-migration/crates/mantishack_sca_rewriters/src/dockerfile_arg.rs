//! Dockerfile `ARG <NAME>=<value>` in-place rewriter — Rust port of the pure
//! core of `packages/sca/rewriters/dockerfile_arg.py`. Content in, content out;
//! the atomic file write stays call-site in Python.

use regex::Regex;

use crate::{py_repr, RewriteEdit, RewriteResult};

/// Apply ARG version-pin edits to Dockerfile `text`, returning the (possibly
/// unchanged) text plus one `RewriteResult` per edit — the pure body of
/// `rewrite_dockerfile_arg` (the read + atomic-write wrapper stays in Python).
pub fn rewrite_dockerfile_arg_text(text: &str, edits: &[RewriteEdit]) -> (String, Vec<RewriteResult>) {
    let mut new_text = text.to_string();
    let mut results = Vec::with_capacity(edits.len());
    for edit in edits {
        let (t, r) = apply_one(&new_text, edit);
        new_text = t;
        results.push(r);
    }
    (new_text, results)
}

fn apply_one(text: &str, edit: &RewriteEdit) -> (String, RewriteResult) {
    // ``^(\s*ARG\s+<name>\s*=\s*)(\S+)`` per line; first match wins.
    let name = regex::escape(&edit.locator);
    let pattern = Regex::new(&format!(r"(?m)^(\s*ARG\s+{name}\s*=\s*)(\S+)")).unwrap();
    let Some(caps) = pattern.captures(text) else {
        return (text.to_string(), RewriteResult::new(edit.clone(), false, "not_found"));
    };
    let g2 = caps.get(2).unwrap();
    let current_value = g2.as_str();
    // Tolerate quoted values: strip outer quotes for comparison (the parser
    // strips quotes when extracting, so edits never carry them).
    let bare_current = current_value.trim_matches('"').trim_matches('\'');
    if bare_current == edit.new_value {
        // Already at target — idempotent skip.
        return (text.to_string(), RewriteResult::new(edit.clone(), false, "no_change"));
    }
    if bare_current != edit.old_value {
        // File's value differs from the plan — refuse to overwrite.
        let reason = format!(
            "value_mismatch: file has {}, plan expected {}",
            py_repr(bare_current),
            py_repr(&edit.old_value),
        );
        return (text.to_string(), RewriteResult::new(edit.clone(), false, &reason));
    }
    // Preserve the original quoting style.
    let new_value_quoted = if current_value.starts_with('"') && current_value.ends_with('"') {
        format!("\"{}\"", edit.new_value)
    } else if current_value.starts_with('\'') && current_value.ends_with('\'') {
        format!("'{}'", edit.new_value)
    } else {
        edit.new_value.clone()
    };
    // Splice: replace just the value span (equivalent to Python's
    // ``pattern.sub(r"\g<1>{new}", text, count=1)`` for the first match, without
    // the replacement-string backreference interpretation).
    let mut new_text = String::with_capacity(text.len());
    new_text.push_str(&text[..g2.start()]);
    new_text.push_str(&new_value_quoted);
    new_text.push_str(&text[g2.end()..]);
    (new_text, RewriteResult::new(edit.clone(), true, "applied"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str, locator: &str, old: &str, new: &str) -> (String, bool, String) {
        let (t, r) = apply_one(text, &RewriteEdit::new(locator, old, new));
        (t, r.applied, r.reason)
    }

    #[test]
    fn apply_one_cases() {
        assert_eq!(one("ARG SEMGREP_VERSION=1.2.3\n", "SEMGREP_VERSION", "1.2.3", "1.3.0"),
            ("ARG SEMGREP_VERSION=1.3.0\n".into(), true, "applied".into()));
        assert_eq!(one("ARG FOO=\"1.2.3\"\n", "FOO", "1.2.3", "1.3.0"),
            ("ARG FOO=\"1.3.0\"\n".into(), true, "applied".into()));
        assert_eq!(one("ARG FOO='1.2.3'\n", "FOO", "1.2.3", "1.3.0"),
            ("ARG FOO='1.3.0'\n".into(), true, "applied".into()));
        assert_eq!(one("ARG OTHER=1\n", "FOO", "1.2.3", "1.3.0"),
            ("ARG OTHER=1\n".into(), false, "not_found".into()));
        assert_eq!(one("ARG FOO=1.3.0\n", "FOO", "1.2.3", "1.3.0"),
            ("ARG FOO=1.3.0\n".into(), false, "no_change".into()));
        assert_eq!(one("ARG FOO=9.9.9\n", "FOO", "1.2.3", "1.3.0"),
            ("ARG FOO=9.9.9\n".into(), false, "value_mismatch: file has '9.9.9', plan expected '1.2.3'".into()));
        // Whitespace around ARG/name/= preserved; value stops before trailing comment.
        assert_eq!(one("   ARG   FOO = 1.2.3   # comment\n", "FOO", "1.2.3", "1.3.0"),
            ("   ARG   FOO = 1.3.0   # comment\n".into(), true, "applied".into()));
        // First matching ARG line in a multi-line file.
        assert_eq!(one("ARG A=1\nARG FOO=1.2.3\nARG B=2\n", "FOO", "1.2.3", "1.3.0"),
            ("ARG A=1\nARG FOO=1.3.0\nARG B=2\n".into(), true, "applied".into()));
    }

    #[test]
    fn multi_edit_sequential() {
        let text = "ARG FOO=1.0.0\nARG BAR=2.0.0\n";
        let edits = [RewriteEdit::new("FOO", "1.0.0", "1.1.0"), RewriteEdit::new("BAR", "2.0.0", "2.2.0")];
        let (new_text, results) = rewrite_dockerfile_arg_text(text, &edits);
        assert_eq!(new_text, "ARG FOO=1.1.0\nARG BAR=2.2.0\n");
        assert!(results.iter().all(|r| r.applied));
    }
}
