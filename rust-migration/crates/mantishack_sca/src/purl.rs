//! purl name/version validators — Rust port of the pure predicates in
//! `packages/sca/purl.py`. The argparse CLI (`main`, `_parse_args`) stays Python.

fn has_whitespace(s: &str) -> bool {
    s.chars().any(|c| c == ' ' || c == '\t' || c == '\n' || c == '\r')
}

/// Reject path-traversal / shell-metachar / whitespace name shapes
/// (`_valid_name`). Only npm-scoped `@scope/name` may contain a slash.
pub fn valid_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    if name.contains('\\') || name.contains("..") {
        return false;
    }
    if has_whitespace(name) {
        return false;
    }
    if name.contains('/') && !(name.starts_with('@') && name.matches('/').count() == 1) {
        return false;
    }
    true
}

/// Reject path-traversal / whitespace / slash version shapes (`_valid_version`).
pub fn valid_version(version: &str) -> bool {
    if version.is_empty() || version == "." || version == ".." {
        return false;
    }
    if version.contains('\\') || version.contains("..") || version.contains('/') {
        return false;
    }
    if has_whitespace(version) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for (n, want) in [
            ("lodash", true), ("@types/node", true), ("org.apache.foo:bar", true), ("", false),
            (".", false), ("..", false), ("a b", false), ("a/b", false), ("@a/b/c", false),
            ("@scope/name", true), ("a..b", false), ("a\\b", false), ("@a", true),
        ] {
            assert_eq!(valid_name(n), want, "{n}");
        }
    }

    #[test]
    fn versions() {
        for (v, want) in [
            ("1.2.3", true), ("", false), ("1.0/2", false), ("1 0", false), ("..", false),
            ("v1.0-beta", true), ("a\\b", false), ("1.2.3.", true),
        ] {
            assert_eq!(valid_version(v), want, "{v}");
        }
    }
}
