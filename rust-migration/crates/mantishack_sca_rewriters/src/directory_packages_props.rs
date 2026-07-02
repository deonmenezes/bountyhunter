//! `Directory.Packages.props` (CPM) rewriter — Rust port of the pure core of
//! `packages/sca/rewriters/directory_packages_props.py`. Content in, content out.

use regex::Regex;

use crate::{apply_named_version_edit, RewriteEdit, RewriteResult};

fn attr_pattern(inc: &str) -> Regex {
    Regex::new(&format!(
        r#"(?i)(?P<open><(?:PackageVersion|GlobalPackageReference)\b)(?P<prefix>[^>]*?Include\s*=\s*['"])(?P<inc>{inc})(?P<inc_close>['"])(?P<mid>[^>]*?Version\s*=\s*['"])(?P<version>[^'"]*)(?P<ver_close>['"])(?P<suffix>[^>]*/?>)"#
    ))
    .unwrap()
}

fn child_pattern(inc: &str) -> Regex {
    Regex::new(&format!(
        r#"(?i)(?P<open><(?:PackageVersion|GlobalPackageReference)\b)(?P<prefix>[^>]*?Include\s*=\s*['"])(?P<inc>{inc})(?P<inc_close>['"])(?P<gap>[^>]*>\s*<Version>\s*)(?P<version>[^<]*?)(?P<post>\s*</Version>\s*</(?:PackageVersion|GlobalPackageReference)>)"#
    ))
    .unwrap()
}

/// Apply `<PackageVersion>` / `<GlobalPackageReference>` version edits to a
/// `Directory.Packages.props` `text` (pure body of
/// `rewrite_directory_packages_props`; fs read/atomic-write stays in Python).
/// Attribute shape first, then the child `<Version>` element.
pub fn rewrite_directory_packages_props_text(
    text: &str,
    edits: &[RewriteEdit],
) -> (String, Vec<RewriteResult>) {
    let mut new_text = text.to_string();
    let mut results = Vec::with_capacity(edits.len());
    for edit in edits {
        let inc = regex::escape(&edit.locator);
        let patterns = [attr_pattern(&inc), child_pattern(&inc)];
        let (t, r) = apply_named_version_edit(&new_text, edit, &patterns, "Version");
        new_text = t;
        results.push(r);
    }
    (new_text, results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str, loc: &str, old: &str, new: &str) -> (String, bool, String) {
        let (t, r) = rewrite_directory_packages_props_text(text, &[RewriteEdit::new(loc, old, new)]);
        (t, r[0].applied, r[0].reason.clone())
    }

    #[test]
    fn dpp_cases() {
        assert_eq!(one("<PackageVersion Include=\"Foo\" Version=\"1.0.0\" />\n", "Foo", "1.0.0", "1.1.0"),
            ("<PackageVersion Include=\"Foo\" Version=\"1.1.0\" />\n".into(), true, "".into()));
        assert_eq!(one("<GlobalPackageReference Include=\"Foo\" Version=\"1.0.0\" />\n", "Foo", "1.0.0", "1.1.0"),
            ("<GlobalPackageReference Include=\"Foo\" Version=\"1.1.0\" />\n".into(), true, "".into()));
        assert_eq!(one("<PackageVersion Include=\"Foo\"><Version>1.0.0</Version></PackageVersion>\n", "Foo", "1.0.0", "1.1.0"),
            ("<PackageVersion Include=\"Foo\"><Version>1.1.0</Version></PackageVersion>\n".into(), true, "".into()));
        assert_eq!(one("<PackageVersion Include=\"Foo\" Version=\"9.9.9\" />\n", "Foo", "1.0.0", "1.1.0"),
            ("<PackageVersion Include=\"Foo\" Version=\"9.9.9\" />\n".into(), false,
             "value_mismatch: file has Version='9.9.9', edit expected '1.0.0'".into()));
        assert_eq!(one("<PackageVersion Include=\"Bar\" Version=\"1.0.0\" />\n", "Foo", "1.0.0", "1.1.0"),
            ("<PackageVersion Include=\"Bar\" Version=\"1.0.0\" />\n".into(), false, "not_found".into()));
    }
}
