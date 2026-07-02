//! Dockerfile `RUN pip install <name>==<version>` rewriter — Rust port of the
//! pure core of `packages/sca/rewriters/dockerfile_inline_install.py`. Content
//! in, content out; the atomic file write stays call-site in Python.

use crate::{py_repr, RewriteEdit, RewriteResult};

/// Apply inline-pip install version-pin edits to Dockerfile `text` (pure body
/// of `rewrite_dockerfile_inline_install`; fs read/atomic-write stays Python).
pub fn rewrite_dockerfile_inline_install_text(
    text: &str,
    edits: &[RewriteEdit],
) -> (String, Vec<RewriteResult>) {
    let mut new_text = text.to_string();
    let mut results = Vec::with_capacity(edits.len());
    for edit in edits {
        let (t, r) = apply_one(&new_text, edit);
        new_text = t;
        results.push(r);
    }
    (new_text, results)
}

fn is_value_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '+' || c == '-'
}

/// Whether `c` is in the negative-lookbehind set `[A-Za-z0-9_.\-]`.
fn is_wordish(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'
}

fn apply_one(text: &str, edit: &RewriteEdit) -> (String, RewriteResult) {
    // Python: ``(?<![A-Za-z0-9_.\-])({name}==)([A-Za-z0-9.+\-]+)`` (first match).
    // The `regex` crate has no lookbehind, so scan literal `<name>==`
    // occurrences and enforce the "not preceded by a word char" guard + a
    // non-empty value run by hand — matching Python's leftmost-match semantics.
    let needle = format!("{}==", edit.locator);
    for (i, _) in text.match_indices(&needle) {
        if i > 0 {
            let prev = text[..i].chars().next_back().unwrap();
            if is_wordish(prev) {
                continue;
            }
        }
        let vstart = i + needle.len();
        let value: String = text[vstart..].chars().take_while(|c| is_value_char(*c)).collect();
        if value.is_empty() {
            continue;
        }
        if value == edit.new_value {
            return (text.to_string(), RewriteResult::new(edit.clone(), false, "no_change"));
        }
        if value != edit.old_value {
            let reason = format!(
                "value_mismatch: file has {}, plan expected {}",
                py_repr(&value),
                py_repr(&edit.old_value),
            );
            return (text.to_string(), RewriteResult::new(edit.clone(), false, &reason));
        }
        let vend = vstart + value.len();
        let mut new_text = String::with_capacity(text.len());
        new_text.push_str(&text[..vstart]);
        new_text.push_str(&edit.new_value);
        new_text.push_str(&text[vend..]);
        return (new_text, RewriteResult::new(edit.clone(), true, "applied"));
    }
    (text.to_string(), RewriteResult::new(edit.clone(), false, "not_found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str, loc: &str, old: &str, new: &str) -> (String, bool, String) {
        let (t, r) = apply_one(text, &RewriteEdit::new(loc, old, new));
        (t, r.applied, r.reason)
    }

    #[test]
    fn apply_inline_cases() {
        assert_eq!(one("RUN pip install foo==1.0.0\n", "foo", "1.0.0", "1.1.0"),
            ("RUN pip install foo==1.1.0\n".into(), true, "applied".into()));
        // Negative lookbehind: name preceded by a word char is not matched.
        assert_eq!(one("RUN pip install myfoo==1.0.0\n", "foo", "1.0.0", "1.1.0"),
            ("RUN pip install myfoo==1.0.0\n".into(), false, "not_found".into()));
        assert_eq!(one("RUN pip install \"foo==1.0.0\"\n", "foo", "1.0.0", "1.1.0"),
            ("RUN pip install \"foo==1.1.0\"\n".into(), true, "applied".into()));
        assert_eq!(one("RUN pip install foo==9.9\n", "foo", "1.0.0", "1.1.0"),
            ("RUN pip install foo==9.9\n".into(), false, "value_mismatch: file has '9.9', plan expected '1.0.0'".into()));
        assert_eq!(one("RUN pip install foo==1.1.0\n", "foo", "1.0.0", "1.1.0"),
            ("RUN pip install foo==1.1.0\n".into(), false, "no_change".into()));
        // Extras (foo[extra]==) are not the <name>== shape → skipped.
        assert_eq!(one("RUN pip install foo[extra]==1.0.0\n", "foo", "1.0.0", "1.1.0"),
            ("RUN pip install foo[extra]==1.0.0\n".into(), false, "not_found".into()));
        // First matching token in a multi-package install line.
        assert_eq!(one("RUN pip install bar==2.0 foo==1.0.0\n", "foo", "1.0.0", "1.1.0"),
            ("RUN pip install bar==2.0 foo==1.1.0\n".into(), true, "applied".into()));
        // Dotted package name.
        assert_eq!(one("RUN pip install ruamel.yaml==0.17\n", "ruamel.yaml", "0.17", "0.18"),
            ("RUN pip install ruamel.yaml==0.18\n".into(), true, "applied".into()));
    }

    #[test]
    fn lookbehind_finds_later_valid_occurrence() {
        // The `=`-preceded second occurrence passes the lookbehind (matches
        // Python's leftmost-valid-position search, not naive non-overlapping).
        let (_, applied, reason) = one("xfoo==foo==2.0\n", "foo", "2.0", "2.1");
        assert!(applied, "reason={reason}");
    }
}
