//! Detect unconditional module-load aborts at file scope — faithful Rust
//! port of `core/inventory/module_load_abort.py`.
//!
//! When a file's top-level execution unconditionally raises / throws /
//! panics before any function binds, no function in that file is
//! reachable through normal import / link. [`detect_module_load_abort`]
//! returns `Some(ModuleLoadAbort)` describing the first such abort, or
//! `None` when none is found (or the language has no detector wired).
//!
//! Conservative bias: only fire when the abort is unambiguously
//! unconditional. A `raise ImportError` inside `if sys.version_info < …:`
//! is NOT flagged; a `panic` gated by `if config == nil` is NOT flagged.
//! False negatives are cheap (miss a deferral); false positives are
//! expensive (silence a real finding on a loadable file).
//!
//! Per-language detection (others return `None` — graceful degradation):
//!   * Python: `raise <AbortException>(…)` at module scope.
//!   * JavaScript / TypeScript: `throw new <Capitalized>(…)` at module
//!     (brace/paren-depth-zero) scope.
//!   * Go: `func init() { panic(…) }` with the panic at the init body's
//!     top scope.
//!   * Rust: `compile_error!(…)` at module scope (not cfg-gated).
//!
//! Port note: the Python detector uses `ast` for the Python branch and
//! returns `None` on `SyntaxError`. This port scans module-scope
//! (column-0) `raise` statements after blanking triple-quoted strings
//! (so a docstring containing a column-0 `raise ImportError(` cannot
//! cause a false positive). It matches the Python behaviour on every
//! tested input; the only divergence is a file with a syntax error
//! elsewhere that still contains a literal module-scope abort — `ast`
//! bails to `None`, the scan still reports it. Such broken files fail
//! extraction upstream before reaching the inventory builder.

use std::sync::OnceLock;

use regex::Regex;

/// Describes a detected unconditional module-load abort.
///
/// `line` is the 1-indexed line of the abort statement; `summary` is a
/// short human-readable label (e.g. `"raise ImportError"`) that
/// consumers display verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleLoadAbort {
    pub line: usize,
    pub summary: String,
}

impl ModuleLoadAbort {
    fn new(line: usize, summary: impl Into<String>) -> Self {
        Self { line, summary: summary.into() }
    }
}

/// Per-language dispatch. Returns the first detected unconditional abort,
/// or `None` when none is detected (or the language has no detector
/// wired). Best-effort: malformed input yields `None`.
pub fn detect_module_load_abort(language: &str, content: &str) -> Option<ModuleLoadAbort> {
    if content.is_empty() {
        return None;
    }
    match language {
        "python" => detect_python(content),
        "javascript" | "typescript" | "tsx" => detect_javascript(content),
        "go" => detect_go(content),
        "rust" => detect_rust(content),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Python — module-scope `raise <AbortException>(…)`.
// ---------------------------------------------------------------------------

const PY_ABORT_EXCEPTIONS: &[&str] = &[
    "ImportError",
    "ModuleNotFoundError",
    "SystemExit",
    "RuntimeError",
    "NotImplementedError",
];

/// A `raise` at column 0 (module scope). Captures the final identifier
/// component of the raised exception, allowing a dotted prefix
/// (`raise pkg.ImportError(…)` → `ImportError`). A bare `raise` or a
/// non-abort exception falls through.
fn py_raise_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)^raise[ \t]+(?:[A-Za-z_][\w.]*\.)?([A-Za-z_]\w*)").unwrap()
    })
}

fn detect_python(content: &str) -> Option<ModuleLoadAbort> {
    // Blank triple-quoted strings so a module docstring containing a
    // column-0 `raise ImportError(` cannot read as a real statement.
    let scrubbed = blank_py_triple_strings(content);
    let bytes = scrubbed.as_bytes();
    for caps in py_raise_re().captures_iter(&scrubbed) {
        let name = caps.get(1).unwrap().as_str();
        if PY_ABORT_EXCEPTIONS.contains(&name) {
            let m = caps.get(0).unwrap();
            return Some(ModuleLoadAbort::new(line_of(bytes, m.start()), format!("raise {name}")));
        }
        // A column-0 non-abort raise (e.g. `raise ValueError`) is still
        // module-scope; keep scanning for a later abort raise, matching
        // the Python AST's in-order `tree.body` walk.
    }
    None
}

/// Replace the contents of Python triple-quoted strings with spaces
/// (newlines preserved) so byte/line offsets stay stable. Best-effort:
/// does not model escaped triple-quotes (rare) or string prefixes beyond
/// the delimiter, which is sufficient for module-scope abort scanning.
fn blank_py_triple_strings(content: &str) -> String {
    let bytes = content.as_bytes();
    let n = bytes.len();
    let mut out = bytes.to_vec();
    let mut i = 0usize;
    while i + 2 < n {
        let is_triple = (bytes[i] == b'"' && bytes[i + 1] == b'"' && bytes[i + 2] == b'"')
            || (bytes[i] == b'\'' && bytes[i + 1] == b'\'' && bytes[i + 2] == b'\'');
        if is_triple {
            let q = bytes[i];
            let mut end = n;
            let mut p = i + 3;
            while p + 2 < n {
                if bytes[p] == q && bytes[p + 1] == q && bytes[p + 2] == q {
                    end = p + 3;
                    break;
                }
                p += 1;
            }
            for slot in out.iter_mut().take(end.min(n)).skip(i) {
                if *slot != b'\n' {
                    *slot = b' ';
                }
            }
            i = end;
            continue;
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| content.to_string())
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript — `throw new <Capitalized>` at depth-zero scope.
// ---------------------------------------------------------------------------

fn js_block_comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)/\*.*?\*/").unwrap())
}

fn js_line_comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"//[^\n]*").unwrap())
}

/// Anchored at the candidate offset (Python uses `re.match(stripped, i)`).
fn js_throw_new_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^throw\s+new\s+([A-Z][A-Za-z0-9_]*)\b").unwrap())
}

fn blank_preserving_newlines(s: &str) -> String {
    s.chars().map(|c| if c == '\n' { '\n' } else { ' ' }).collect()
}

fn js_strip_comments(content: &str) -> String {
    let no_block = js_block_comment_re()
        .replace_all(content, |c: &regex::Captures| blank_preserving_newlines(&c[0]))
        .into_owned();
    js_line_comment_re()
        .replace_all(&no_block, |c: &regex::Captures| blank_preserving_newlines(&c[0]))
        .into_owned()
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn detect_javascript(content: &str) -> Option<ModuleLoadAbort> {
    let stripped = js_strip_comments(content);
    let bytes = stripped.as_bytes();
    let n = bytes.len();
    let (mut depth, mut paren) = (0i32, 0i32);
    let mut i = 0usize;
    while i < n {
        let c = bytes[i];
        if c == b'"' || c == b'\'' || c == b'`' {
            match skip_string(bytes, i) {
                Some(j) => {
                    i = j;
                    continue;
                }
                None => break,
            }
        }
        match c {
            b'{' => depth += 1,
            b'}' => depth = (depth - 1).max(0),
            b'(' => paren += 1,
            b')' => paren = (paren - 1).max(0),
            b't' if depth == 0 && paren == 0 => {
                // `\b` before `throw`: a word-char immediately before
                // breaks the boundary (`xthrow` must not match).
                let boundary = i == 0 || !is_word_byte(bytes[i - 1]);
                if boundary {
                    if let Some(caps) = js_throw_new_re().captures(&stripped[i..]) {
                        let name = caps.get(1).unwrap().as_str();
                        return Some(ModuleLoadAbort::new(
                            line_of(bytes, i),
                            format!("throw new {name}"),
                        ));
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Go — `func init() { panic(…) }` with the panic at the body's top scope.
// ---------------------------------------------------------------------------

fn go_init_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bfunc\s+init\s*\(\s*\)\s*\{").unwrap())
}

fn go_panic_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bpanic\s*\(").unwrap())
}

fn detect_go(content: &str) -> Option<ModuleLoadAbort> {
    let bytes = content.as_bytes();
    let init = go_init_header_re().find(content)?;
    let body_start = init.end();
    let body_end = go_find_matching_brace(bytes, body_start - 1)?;
    let init_body = &content[body_start..body_end];
    let panic = go_panic_call_re().find(init_body)?;
    if !go_panic_is_unconditional(init_body.as_bytes(), panic.start()) {
        return None;
    }
    let abs_offset = body_start + panic.start();
    Some(ModuleLoadAbort::new(line_of(bytes, abs_offset), "func init() { panic(...) }"))
}

/// Given the byte index of an opening `{`, return the matching `}`.
/// Skips Go string literals (interpreted `"…"` and raw `` `…` ``). Does
/// NOT skip `//` comments — faithful to the Python original.
fn go_find_matching_brace(src: &[u8], open_pos: usize) -> Option<usize> {
    if open_pos >= src.len() || src[open_pos] != b'{' {
        return None;
    }
    let mut depth: i32 = 1;
    let mut i = open_pos + 1;
    let n = src.len();
    while i < n && depth > 0 {
        let c = src[i];
        if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        } else if c == b'"' || c == b'`' {
            match go_skip_string(src, i) {
                Some(j) => {
                    i = j;
                    continue;
                }
                None => return None,
            }
        }
        i += 1;
    }
    None
}

fn go_skip_string(src: &[u8], start: usize) -> Option<usize> {
    let quote = src[start];
    let mut i = start + 1;
    let n = src.len();
    while i < n {
        let c = src[i];
        if c == b'\\' && quote == b'"' {
            i += 2;
            continue;
        }
        if c == quote {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

fn go_panic_is_unconditional(body: &[u8], panic_offset: usize) -> bool {
    let mut depth = 0i32;
    let mut i = 0usize;
    while i < panic_offset {
        let c = body[i];
        if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth = (depth - 1).max(0);
        } else if c == b'"' || c == b'`' {
            match go_skip_string(body, i) {
                Some(j) => {
                    i = j;
                    continue;
                }
                None => return false,
            }
        }
        i += 1;
    }
    depth == 0
}

// ---------------------------------------------------------------------------
// Rust — `compile_error!(…)` at module scope (not cfg-gated).
// ---------------------------------------------------------------------------

fn rust_compile_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*compile_error\s*!\s*\(").unwrap())
}

fn detect_rust(content: &str) -> Option<ModuleLoadAbort> {
    let m = rust_compile_error_re().find(content)?;
    // If the preceding non-whitespace token is `]` (end of an attribute
    // like `#[cfg(...)]`), the macro is conditional — skip it.
    if content[..m.start()].trim_end().ends_with(']') {
        return None;
    }
    Some(ModuleLoadAbort::new(line_of(content.as_bytes(), m.start()), "compile_error!(...)"))
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

fn line_of(src: &[u8], pos: usize) -> usize {
    src[..pos].iter().filter(|&&b| b == b'\n').count() + 1
}

/// Advance past a JS string / template / char literal starting at the
/// opening quote `start`. Handles backslash escapes; template interiors
/// are treated opaquely (conservative).
fn skip_string(src: &[u8], start: usize) -> Option<usize> {
    let quote = src[start];
    let mut i = start + 1;
    let n = src.len();
    while i < n {
        let c = src[i];
        if c == b'\\' {
            i += 2;
            continue;
        }
        if c == quote {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(language: &str, content: &str) -> ModuleLoadAbort {
        detect_module_load_abort(language, content).expect("expected an abort")
    }

    // --- Python -----------------------------------------------------------

    #[test]
    fn python_top_level_raise_import_error_fires() {
        let src = "import sys\nraise ImportError(\"disabled\")\ndef f():\n    pass\n";
        let a = hit("python", src);
        assert_eq!(a.line, 2);
        assert_eq!(a.summary, "raise ImportError");
    }

    #[test]
    fn python_module_not_found_error_fires() {
        assert_eq!(hit("python", "raise ModuleNotFoundError()\n").summary, "raise ModuleNotFoundError");
    }

    #[test]
    fn python_system_exit_fires() {
        assert_eq!(hit("python", "raise SystemExit(1)\n").summary, "raise SystemExit");
    }

    #[test]
    fn python_conditional_raise_does_not_fire() {
        let src = "import sys\nif sys.version_info < (3, 10):\n    raise ImportError(\"old\")\ndef f():\n    pass\n";
        assert_eq!(detect_module_load_abort("python", src), None);
    }

    #[test]
    fn python_raise_inside_try_does_not_fire() {
        let src = "try:\n    import x\nexcept ImportError:\n    raise ImportError(\"x\")\n";
        assert_eq!(detect_module_load_abort("python", src), None);
    }

    #[test]
    fn python_raise_inside_function_does_not_fire() {
        let src = "def f():\n    raise ImportError(\"x\")\n";
        assert_eq!(detect_module_load_abort("python", src), None);
    }

    #[test]
    fn python_non_abort_exception_does_not_fire() {
        assert_eq!(detect_module_load_abort("python", "raise ValueError(\"x\")\n"), None);
    }

    #[test]
    fn python_syntax_error_returns_none() {
        assert_eq!(detect_module_load_abort("python", "def (:\n"), None);
    }

    #[test]
    fn python_dotted_exception_name_fires() {
        assert_eq!(hit("python", "raise errors.ImportError(\"x\")\n").summary, "raise ImportError");
    }

    #[test]
    fn python_docstring_raise_does_not_false_positive() {
        // A module docstring whose body has a column-0 `raise ImportError(`
        // must NOT be flagged — it's string content, not a statement.
        let src = "\"\"\"\nraise ImportError(here)\n\"\"\"\ndef f():\n    pass\n";
        assert_eq!(detect_module_load_abort("python", src), None);
    }

    // --- JavaScript / TypeScript -----------------------------------------

    #[test]
    fn js_top_level_throw_fires() {
        let src = "const x = 1;\nthrow new Error(\"disabled\");\nfunction f() {}\n";
        let a = hit("javascript", src);
        assert_eq!(a.line, 2);
        assert_eq!(a.summary, "throw new Error");
    }

    #[test]
    fn js_typescript_alias_fires() {
        assert_eq!(hit("typescript", "throw new TypeError(\"x\");\n").summary, "throw new TypeError");
    }

    #[test]
    fn js_throw_inside_function_does_not_fire() {
        let src = "function f() {\n  throw new Error(\"x\");\n}\n";
        assert_eq!(detect_module_load_abort("javascript", src), None);
    }

    #[test]
    fn js_throw_inside_if_does_not_fire() {
        let src = "if (flag) {\n  throw new Error(\"x\");\n}\n";
        assert_eq!(detect_module_load_abort("javascript", src), None);
    }

    #[test]
    fn js_commented_throw_does_not_fire() {
        let src = "// throw new Error(\"x\");\n/* throw new Error() */\nconst ok = 1;\n";
        assert_eq!(detect_module_load_abort("javascript", src), None);
    }

    #[test]
    fn js_throw_in_fn_with_string_brace_does_not_fire() {
        let src = "function f() {\n  const s = \"}\";\n  throw new Error(s);\n}\n";
        assert_eq!(detect_module_load_abort("javascript", src), None);
    }

    #[test]
    fn js_arrow_function_throw_does_not_fire() {
        let src = "const f = () => {\n  throw new Error(\"x\");\n};\n";
        assert_eq!(detect_module_load_abort("javascript", src), None);
    }

    // --- Go ---------------------------------------------------------------

    #[test]
    fn go_init_unconditional_panic_fires() {
        let src = "package main\n\nfunc init() {\n    panic(\"disabled\")\n}\n";
        assert_eq!(hit("go", src).summary, "func init() { panic(...) }");
    }

    #[test]
    fn go_init_conditional_panic_does_not_fire() {
        let src = "package main\n\nfunc init() {\n    if cfg == nil {\n        panic(\"x\")\n    }\n}\n";
        assert_eq!(detect_module_load_abort("go", src), None);
    }

    #[test]
    fn go_no_init_does_not_fire() {
        let src = "package main\n\nfunc other() {\n    panic(\"x\")\n}\n";
        assert_eq!(detect_module_load_abort("go", src), None);
    }

    // --- Rust -------------------------------------------------------------

    #[test]
    fn rust_compile_error_fires() {
        assert_eq!(hit("rust", "compile_error!(\"disabled\");\nfn f() {}\n").summary, "compile_error!(...)");
    }

    #[test]
    fn rust_cfg_gated_compile_error_does_not_fire() {
        assert_eq!(
            detect_module_load_abort("rust", "#[cfg(feature = \"x\")]\ncompile_error!(\"x\");\n"),
            None
        );
    }

    // --- Cross-cutting ----------------------------------------------------

    #[test]
    fn empty_content_returns_none() {
        assert_eq!(detect_module_load_abort("python", ""), None);
    }

    #[test]
    fn unwired_language_returns_none() {
        assert_eq!(detect_module_load_abort("ruby", "raise 'x'\n"), None);
    }

    #[test]
    fn clean_python_file_returns_none() {
        assert_eq!(detect_module_load_abort("python", "def handler(x):\n    return x\n"), None);
    }
}
