//! Helm `Chart.yaml` dependency-version rewriter — Rust port of the pure core
//! of `packages/sca/rewriters/helm_chart.py`. Content in, content out.
//!
//! The two dep-block shapes (name-then-version, version-then-name) are matched
//! with a same-indent backreference (`\k<indent>`) and a `(?!-)` line-start
//! lookahead, so these patterns run on `fancy-regex`. The substitution rebuilds
//! the block (normalising the `- name:` / `version:` lines) exactly as Python's
//! `pattern.sub` does.

use fancy_regex::{Captures, Regex};

use crate::{py_repr, RewriteEdit, RewriteResult};

fn name_first_pattern(locator: &str) -> Regex {
    Regex::new(&format!(
        r#"(?m)^(?P<indent>\s+)- name:\s*{locator}\s*\n(?P<between>(?:\s*(?!-).+\n)*?)(?P<prefix>\k<indent>\s+version:\s*["']?)(?P<ver>[^\s"'#]+)(?P<suffix>["']?\s*(?:#[^\n]*)?\n)"#
    ))
    .unwrap()
}

fn version_first_pattern(locator: &str) -> Regex {
    Regex::new(&format!(
        r#"(?m)^(?P<indent>\s+)- version:\s*["']?(?P<ver>[^\s"'#]+)["']?\s*(?:#[^\n]*)?\n(?P<between>(?:\s*(?!-).+\n)*?)\k<indent>\s+name:\s*{locator}\s*\n"#
    ))
    .unwrap()
}

/// Apply chart-dependency version edits to a `Chart.yaml` `text` (pure body of
/// `rewrite_chart_yaml`; fs read/atomic-write stays in Python).
pub fn rewrite_chart_yaml_text(text: &str, edits: &[RewriteEdit]) -> (String, Vec<RewriteResult>) {
    let mut new_text = text.to_string();
    let mut results = Vec::with_capacity(edits.len());
    for edit in edits {
        let (t, r) = apply_one_chart(&new_text, edit);
        new_text = t;
        results.push(r);
    }
    (new_text, results)
}

fn apply_one_chart(text: &str, edit: &RewriteEdit) -> (String, RewriteResult) {
    let loc = fancy_regex::escape(&edit.locator);
    let name_first = name_first_pattern(&loc);
    let version_first = version_first_pattern(&loc);

    let (caps, shape) = match name_first.captures(text) {
        Ok(Some(c)) => (c, Shape::NameFirst),
        _ => match version_first.captures(text) {
            Ok(Some(c)) => (c, Shape::VersionFirst),
            _ => return (text.to_string(), RewriteResult::new(edit.clone(), false, "not_found")),
        },
    };

    let current_ver = caps.name("ver").unwrap().as_str();
    if current_ver == edit.new_value {
        return (text.to_string(), RewriteResult::new(edit.clone(), false, "no_change"));
    }
    if current_ver != edit.old_value {
        let reason = format!(
            "value_mismatch: file has {}, plan expected {}",
            py_repr(current_ver),
            py_repr(&edit.old_value),
        );
        return (text.to_string(), RewriteResult::new(edit.clone(), false, &reason));
    }

    let whole = caps.get(0).unwrap();
    let rebuilt = rebuild(&caps, shape, edit);
    let mut new_text = String::with_capacity(text.len());
    new_text.push_str(&text[..whole.start()]);
    new_text.push_str(&rebuilt);
    new_text.push_str(&text[whole.end()..]);
    (new_text, RewriteResult::new(edit.clone(), true, "applied"))
}

#[derive(Clone, Copy)]
enum Shape {
    NameFirst,
    VersionFirst,
}

fn rebuild(caps: &Captures, shape: Shape, edit: &RewriteEdit) -> String {
    let g = |n: &str| caps.name(n).map(|m| m.as_str()).unwrap_or("");
    let indent = g("indent");
    let between = g("between");
    match shape {
        // ``{indent}- name: {locator}\n{between}{prefix}{new}{suffix}``
        Shape::NameFirst => format!(
            "{indent}- name: {loc}\n{between}{prefix}{new}{suffix}",
            loc = edit.locator,
            prefix = g("prefix"),
            new = edit.new_value,
            suffix = g("suffix"),
        ),
        // ``{indent}- version: {new}\n{between}{indent}  name: {locator}\n``
        Shape::VersionFirst => format!(
            "{indent}- version: {new}\n{between}{indent}  name: {loc}\n",
            new = edit.new_value,
            loc = edit.locator,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str, loc: &str, old: &str, new: &str) -> (String, bool, String) {
        let (t, r) = apply_one_chart(text, &RewriteEdit::new(loc, old, new));
        (t, r.applied, r.reason)
    }

    #[test]
    fn helm_cases() {
        let nf = "apiVersion: v2\ndependencies:\n  - name: postgresql\n    version: 12.1.0\n    repository: https://charts\n";
        assert_eq!(one(nf, "postgresql", "12.1.0", "12.2.0"),
            ("apiVersion: v2\ndependencies:\n  - name: postgresql\n    version: 12.2.0\n    repository: https://charts\n".into(), true, "applied".into()));

        let vf = "dependencies:\n  - version: 12.1.0\n    name: postgresql\n";
        assert_eq!(one(vf, "postgresql", "12.1.0", "12.2.0"),
            ("dependencies:\n  - version: 12.2.0\n    name: postgresql\n".into(), true, "applied".into()));

        let quoted = "dependencies:\n  - name: redis\n    version: \"17.0.0\"\n";
        assert_eq!(one(quoted, "redis", "17.0.0", "18.0.0"),
            ("dependencies:\n  - name: redis\n    version: \"18.0.0\"\n".into(), true, "applied".into()));

        assert_eq!(one(nf, "postgresql", "9.9.9", "12.2.0"),
            (nf.into(), false, "value_mismatch: file has '12.1.0', plan expected '9.9.9'".into()));
        assert_eq!(one(nf, "mysql", "1.0", "1.1"), (nf.into(), false, "not_found".into()));

        // Idempotent no_change (file already at new version).
        let at_target = "dependencies:\n  - name: redis\n    version: 18.0.0\n";
        assert_eq!(one(at_target, "redis", "17.0.0", "18.0.0").2, "no_change");
    }
}
