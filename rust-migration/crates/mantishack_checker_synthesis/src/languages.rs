//! Engine selection — faithful port of `packages/checker_synthesis/languages.py`.
//!
//! Coccinelle for C source/headers (`.c` / `.h`); Semgrep for every other
//! language we support; `None` for files we can't classify.

// C source / header — Coccinelle's home turf.
const COCCINELLE_EXTS: &[&str] = &[".c", ".h"];

// Languages Semgrep handles (not exhaustive — mirrors the Python set exactly).
const SEMGREP_EXTS: &[&str] = &[
    ".py", ".pyi",
    ".java",
    ".go",
    ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx",
    ".rb",
    ".rs",
    ".php",
    ".cs",
    ".kt", ".kts",
    ".scala",
    ".swift",
    ".lua",
    ".ex", ".exs",
    // C++: route to Semgrep (Coccinelle's C++ support is weak).
    ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".c++",
];

/// Faithful reimplementation of `pathlib.PurePosixPath(file_path).suffix`
/// for the realistic case of a repo-relative source-file path.
///
/// pathlib: `name` is the final path component (trailing separators stripped);
/// `suffix = name[i:]` where `i = name.rfind('.')`, but only when
/// `0 < i < len(name) - 1`, else `''`.
fn py_suffix(file_path: &str) -> String {
    let trimmed = file_path.trim_end_matches('/');
    let name = trimmed.rsplit('/').next().unwrap_or(trimmed);
    match name.rfind('.') {
        // i > 0 (not a leading-dot hidden name) and i < len-1 (not a trailing dot).
        Some(i) if i > 0 && i < name.len() - 1 => name[i..].to_string(),
        _ => String::new(),
    }
}

/// Pick the synthesis engine for a source file.
///
/// `"coccinelle"` for C/C++ headers+sources routed to it, `"semgrep"` for
/// everything else we support, or `None` for unrecognised files.
pub fn detect_engine(file_path: &str) -> Option<&'static str> {
    if file_path.is_empty() {
        return None;
    }
    let suffix = py_suffix(file_path).to_lowercase();
    if suffix.is_empty() {
        return None;
    }
    if COCCINELLE_EXTS.contains(&suffix.as_str()) {
        return Some("coccinelle");
    }
    if SEMGREP_EXTS.contains(&suffix.as_str()) {
        return Some("semgrep");
    }
    None
}

/// The engines this package can synthesise rules for.
pub fn supported_engines() -> (&'static str, &'static str) {
    ("semgrep", "coccinelle")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors mirror packages/checker_synthesis/tests/test_languages.py.
    #[test]
    fn c_picks_coccinelle() {
        for p in ["src/foo.c", "include/bar.h", "drivers/net/dev.c", "kernel/sched.c"] {
            assert_eq!(detect_engine(p), Some("coccinelle"), "{p}");
        }
    }

    #[test]
    fn other_languages_pick_semgrep() {
        for (p, e) in [
            ("src/foo.py", "semgrep"),
            ("src/Foo.java", "semgrep"),
            ("cmd/main.go", "semgrep"),
            ("src/app.js", "semgrep"),
            ("src/app.ts", "semgrep"),
            ("src/app.tsx", "semgrep"),
            ("lib/a.rb", "semgrep"),
            ("src/main.rs", "semgrep"),
            ("src/PHPFile.php", "semgrep"),
        ] {
            assert_eq!(detect_engine(p), Some(e), "{p}");
        }
    }

    #[test]
    fn unknown_returns_none() {
        for p in ["Makefile", "README", "docs/notes.txt", "data.bin", "image.png", ""] {
            assert_eq!(detect_engine(p), None, "{p}");
        }
    }

    #[test]
    fn case_insensitive_extension() {
        assert_eq!(detect_engine("src/Foo.PY"), Some("semgrep"));
        assert_eq!(detect_engine("src/Foo.C"), Some("coccinelle"));
    }

    #[test]
    fn supported_engines_tuple() {
        assert_eq!(supported_engines(), ("semgrep", "coccinelle"));
    }

    #[test]
    fn hidden_files_and_trailing_dot_have_no_suffix() {
        // pathlib: leading-dot name and trailing-dot name → no suffix.
        assert_eq!(detect_engine(".c"), None); // ".c" name, dot at index 0
        assert_eq!(detect_engine("foo."), None); // trailing dot
        assert_eq!(detect_engine("src/.hidden"), None);
        assert_eq!(detect_engine("a.tar.c"), Some("coccinelle")); // last suffix wins
    }
}
