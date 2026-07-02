//! `.csproj` / `.fsproj` / `.vbproj` PackageReference rewriter — Rust port of
//! the pure core of `packages/sca/rewriters/csproj.py`. Content in, content out.

use regex::Regex;

use crate::{apply_named_version_edit, RewriteEdit, RewriteResult};

fn inline_version_pattern(inc: &str) -> Regex {
    Regex::new(&format!(
        r#"(?i)(?P<open><PackageReference\b)(?P<prefix>[^>]*?Include\s*=\s*['"])(?P<inc>{inc})(?P<inc_close>['"])(?P<mid>[^>]*?Version\s*=\s*['"])(?P<version>[^'"]*)(?P<ver_close>['"])"#
    ))
    .unwrap()
}

fn version_override_pattern(inc: &str) -> Regex {
    Regex::new(&format!(
        r#"(?i)(?P<open><PackageReference\b)(?P<prefix>[^>]*?Include\s*=\s*['"])(?P<inc>{inc})(?P<inc_close>['"])(?P<mid>[^>]*?VersionOverride\s*=\s*['"])(?P<version>[^'"]*)(?P<ver_close>['"])"#
    ))
    .unwrap()
}

fn child_version_pattern(inc: &str) -> Regex {
    Regex::new(&format!(
        r#"(?i)(?P<open><PackageReference\b)(?P<prefix>[^>]*?Include\s*=\s*['"])(?P<inc>{inc})(?P<inc_close>['"])(?P<gap>[^>]*>\s*<Version>\s*)(?P<version>[^<]*?)(?P<post>\s*</Version>\s*</PackageReference>)"#
    ))
    .unwrap()
}

/// Apply `<PackageReference>` Version / VersionOverride / child-element edits to
/// `.csproj` `text` (pure body of `rewrite_csproj`; fs read/atomic-write stays
/// in Python). Preference order: inline `Version=`, then `VersionOverride=`,
/// then a child `<Version>` element.
pub fn rewrite_csproj_text(text: &str, edits: &[RewriteEdit]) -> (String, Vec<RewriteResult>) {
    let mut new_text = text.to_string();
    let mut results = Vec::with_capacity(edits.len());
    for edit in edits {
        let inc = regex::escape(&edit.locator);
        let patterns = [
            inline_version_pattern(&inc),
            version_override_pattern(&inc),
            child_version_pattern(&inc),
        ];
        let (t, r) = apply_named_version_edit(&new_text, edit, &patterns, "version");
        new_text = t;
        results.push(r);
    }
    (new_text, results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str, loc: &str, old: &str, new: &str) -> (String, bool, String) {
        let (t, r) = rewrite_csproj_text(text, &[RewriteEdit::new(loc, old, new)]);
        (t, r[0].applied, r[0].reason.clone())
    }

    #[test]
    fn csproj_cases() {
        assert_eq!(one("<PackageReference Include=\"Newtonsoft.Json\" Version=\"12.0.1\" />\n", "Newtonsoft.Json", "12.0.1", "13.0.1"),
            ("<PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.1\" />\n".into(), true, "".into()));
        // NuGet name match is case-insensitive.
        assert_eq!(one("<PackageReference Include=\"newtonsoft.json\" Version=\"12.0.1\" />\n", "Newtonsoft.Json", "12.0.1", "13.0.1"),
            ("<PackageReference Include=\"newtonsoft.json\" Version=\"13.0.1\" />\n".into(), true, "".into()));
        assert_eq!(one("<PackageReference Include=\"Foo\" VersionOverride=\"1.0.0\" />\n", "Foo", "1.0.0", "1.1.0"),
            ("<PackageReference Include=\"Foo\" VersionOverride=\"1.1.0\" />\n".into(), true, "".into()));
        assert_eq!(one("<PackageReference Include=\"Foo\"><Version>1.0.0</Version></PackageReference>\n", "Foo", "1.0.0", "1.1.0"),
            ("<PackageReference Include=\"Foo\"><Version>1.1.0</Version></PackageReference>\n".into(), true, "".into()));
        assert_eq!(one("<PackageReference Include='Foo' Version='1.0.0' />\n", "Foo", "1.0.0", "1.1.0"),
            ("<PackageReference Include='Foo' Version='1.1.0' />\n".into(), true, "".into()));
        assert_eq!(one("<PackageReference Include=\"Foo\" Version=\"9.9.9\" />\n", "Foo", "1.0.0", "1.1.0"),
            ("<PackageReference Include=\"Foo\" Version=\"9.9.9\" />\n".into(), false,
             "value_mismatch: file has version='9.9.9', edit expected '1.0.0'".into()));
        assert_eq!(one("<PackageReference Include=\"Bar\" Version=\"1.0.0\" />\n", "Foo", "1.0.0", "1.1.0"),
            ("<PackageReference Include=\"Bar\" Version=\"1.0.0\" />\n".into(), false, "not_found".into()));
    }
}
