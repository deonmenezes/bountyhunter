//! YAML `image: <ref>:<tag>` in-place rewriter (compose / k8s / gitlab-ci) —
//! Rust port of the pure core of `packages/sca/rewriters/yaml_image.py`.
//! Content in, content out; the atomic file write stays call-site in Python.

use regex::Regex;

use crate::{docker_image_forms, py_repr, RewriteEdit, RewriteResult};

/// Apply image-tag edits to YAML `image:` lines in `text` (pure body of
/// `rewrite_yaml_image`; fs read/atomic-write stays in Python).
pub fn rewrite_yaml_image_text(text: &str, edits: &[RewriteEdit]) -> (String, Vec<RewriteResult>) {
    let mut new_text = text.to_string();
    let mut results = Vec::with_capacity(edits.len());
    for edit in edits {
        let (t, r) = apply_one_image(&new_text, edit);
        new_text = t;
        results.push(r);
    }
    (new_text, results)
}

fn apply_one_image(text: &str, edit: &RewriteEdit) -> (String, RewriteResult) {
    let forms = docker_image_forms(&edit.locator);
    let image_alternates = forms.iter().map(|f| regex::escape(f)).collect::<Vec<_>>().join("|");
    // YAML image: shape — bare, quoted, or after a `- ` list marker.
    let pattern = Regex::new(&format!(
        r#"(?m)^(\s*(?:-\s+)?image:\s*["']?(?:{image_alternates}):)([^\s"'#]+)(["'\s#]|$)"#
    ))
    .unwrap();
    let Some(caps) = pattern.captures(text) else {
        return (text.to_string(), RewriteResult::new(edit.clone(), false, "not_found"));
    };
    let g2 = caps.get(2).unwrap();
    let current_tag = g2.as_str();
    if current_tag == edit.new_value {
        return (text.to_string(), RewriteResult::new(edit.clone(), false, "no_change"));
    }
    if current_tag != edit.old_value {
        let reason = format!(
            "value_mismatch: file has {}, plan expected {}",
            py_repr(current_tag),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str, loc: &str, old: &str, new: &str) -> (String, bool, String) {
        let (t, r) = apply_one_image(text, &RewriteEdit::new(loc, old, new));
        (t, r.applied, r.reason)
    }

    #[test]
    fn apply_image_cases() {
        assert_eq!(one("    image: foo/bar:1.0\n", "foo/bar", "1.0", "1.1"),
            ("    image: foo/bar:1.1\n".into(), true, "applied".into()));
        assert_eq!(one("    image: \"foo/bar:1.0\"\n", "foo/bar", "1.0", "1.1"),
            ("    image: \"foo/bar:1.1\"\n".into(), true, "applied".into()));
        assert_eq!(one("    - image: foo/bar:1.0\n", "foo/bar", "1.0", "1.1"),
            ("    - image: foo/bar:1.1\n".into(), true, "applied".into()));
        assert_eq!(one("    image: python:3.12\n", "docker.io/library/python", "3.12", "3.13"),
            ("    image: python:3.13\n".into(), true, "applied".into()));
        assert_eq!(one("    image: foo/bar:1.0  # pin\n", "foo/bar", "1.0", "1.1"),
            ("    image: foo/bar:1.1  # pin\n".into(), true, "applied".into()));
        assert_eq!(one("    image: foo/bar:1.1\n", "foo/bar", "1.0", "1.1"),
            ("    image: foo/bar:1.1\n".into(), false, "no_change".into()));
        assert_eq!(one("    image: foo/bar:9.9\n", "foo/bar", "1.0", "1.1"),
            ("    image: foo/bar:9.9\n".into(), false, "value_mismatch: file has '9.9', plan expected '1.0'".into()));
        assert_eq!(one("    image: other/thing:1.0\n", "foo/bar", "1.0", "1.1"),
            ("    image: other/thing:1.0\n".into(), false, "not_found".into()));
    }
}
