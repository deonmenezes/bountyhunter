//! Test-file / test-directory detection — Rust port of
//! `packages/sca/_test_paths.py`. Pure over path strings; shared by the
//! filesystem walkers (which pass already-resolved paths).

use std::sync::OnceLock;

use regex::Regex;

/// Directory names that mark a test tree (`TEST_DIR_NAMES`).
pub const TEST_DIR_NAMES: &[&str] = &["tests", "test", "__tests__", "spec", "e2e"];

fn test_file_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"^(",
            r"test_.*\.py",
            r"|.*_test\.py",
            r"|.*\.test\.(?:py|js|ts|jsx|tsx|mjs|cjs)",
            r"|.*\.spec\.(?:py|js|ts|jsx|tsx|mjs|cjs)",
            r"|.*_test\.go",
            r"|.*_test\.rb",
            r"|.*_spec\.rb",
            r"|.*Test\.(?:java|kt)",
            r"|.*Tests\.(?:java|kt)",
            r"|.*IT\.(?:java|kt)",
            r"|.*_test\.rs",
            r"|.*Test\.cs",
            r"|.*Tests\.cs",
            r"|.*Test\.php",
            r")$",
        ))
        .unwrap()
    })
}

fn basename(path: &str) -> &str {
    path.rsplit_once('/').map(|(_, n)| n).unwrap_or(path)
}

/// `Path.relative_to(target)` for path strings, returning the full path when
/// `path` isn't under `target` (Python's `ValueError` fallback).
fn relative_to<'a>(path: &'a str, target: &str) -> &'a str {
    if path == target {
        return "";
    }
    if let Some(rest) = path.strip_prefix(target) {
        if let Some(r) = rest.strip_prefix('/') {
            return r;
        }
    }
    path
}

/// True if `path` is part of the project's test suite (`is_test_path`): a
/// test-file naming convention on the basename, or a test-directory ancestor
/// (bounded by `target`).
pub fn is_test_path(path: &str, target: &str) -> bool {
    if test_file_re().is_match(basename(path)) {
        return true;
    }
    relative_to(path, target).split('/').any(|part| TEST_DIR_NAMES.contains(&part))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_test_paths() {
        assert!(is_test_path("src/test_foo.py", "src"));
        assert!(is_test_path("a/foo_test.py", "a"));
        assert!(is_test_path("a/foo.spec.ts", "a"));
        assert!(is_test_path("pkg/foo_test.go", "pkg"));
        assert!(is_test_path("src/FooTest.java", "src"));
        assert!(!is_test_path("src/foo.py", "src"));
        assert!(is_test_path("proj/tests/helper.py", "proj"));
        assert!(is_test_path("proj/a/__tests__/x.js", "proj"));
        assert!(is_test_path("proj/e2e/x.py", "proj"));
        // target's own `tests` component is stripped by relative_to.
        assert!(!is_test_path("x/tests/foo.py", "x/tests"));
        // Path not under target -> full-path ancestor check still finds `tests`.
        assert!(is_test_path("/abs/tests/y.py", "proj"));
    }
}
