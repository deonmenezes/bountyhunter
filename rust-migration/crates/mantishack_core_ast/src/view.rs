//! Composition layer: build a [`FunctionView`] over the inventory substrate —
//! Rust port of `core/ast/view.py`.
//!
//! The public entry point [`view`] is the only function callers should need.
//! Everything else here is per-language helper plumbing.
//!
//! Implementation notes (mirroring the Python module):
//!
//!   * Function discovery routes through
//!     [`mantishack_core_inventory::ts_extract::extract_functions`], which does
//!     language dispatch and tree-sitter/regex fallback.
//!   * Calls extraction routes through the per-language
//!     `extract_call_graph_<lang>` in `mantishack_core_inventory::call_graph`;
//!     the dispatch table is local to this module. Languages absent from the
//!     table return an empty calls list.
//!   * Returns / inline-asm are extracted here per-language. Tree-sitter
//!     languages (C, C++, JavaScript, Java, Go) walk `return_statement` nodes via
//!     the shared `mantishack_ts` parser; Python uses rustpython. A missing/
//!     unparseable input degrades cleanly to "no returns" rather than crashing.
//!
//! Language coverage matches the Python revision:
//!   * Calls + returns + asm: C, C++ (asm is C/C++ only)
//!   * Calls + returns: Python, JavaScript, Java, Go
//!   * Calls only (inherited from inventory): Rust, Ruby, C#, PHP, TypeScript
//!     (TS shares the JS walker)

use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

use mantishack_core_inventory::call_graph::{
    extract_call_graph_c, extract_call_graph_cpp, extract_call_graph_csharp,
    extract_call_graph_go, extract_call_graph_java, extract_call_graph_javascript,
    extract_call_graph_php, extract_call_graph_python, extract_call_graph_ruby,
    extract_call_graph_rust, CallSite,
};
use mantishack_core_inventory::detect_language;
use mantishack_core_inventory::ts_extract::extract_functions;

use crate::model::{FunctionView, Return, SCHEMA_VERSION};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Return a [`FunctionView`] for `function` in `path`.
///
/// Returns `None` when:
///   * The language can't be detected from the extension (pass `language` to
///     override).
///   * The file can't be read.
///   * No function in the file matches `function` (and `at_line` when given).
///
/// When multiple functions in the file share the same name (e.g. methods of
/// different classes), pass `at_line` to disambiguate — the first match whose
/// line range contains `at_line` is returned. Without `at_line`, the first name
/// match wins (extractor output order).
pub fn view(
    path: &Path,
    function: &str,
    at_line: Option<i64>,
    language: Option<&str>,
) -> Option<FunctionView> {
    // Language detection happens before the read, matching Python: a missing
    // file with a known extension still resolves a language, then the read
    // fails and yields None.
    let language: String = match language {
        Some(l) => l.to_string(),
        None => {
            let p = path.to_string_lossy();
            match detect_language(p.as_ref()) {
                Some(l) => l.to_string(),
                None => return None,
            }
        }
    };

    // Read with lossy UTF-8 decoding (Python uses errors="replace"). A read
    // failure (missing file, etc.) yields None (Python catches OSError).
    let bytes = std::fs::read(path).ok()?;
    let content = String::from_utf8_lossy(&bytes).into_owned();

    // Function discovery — inventory handles per-language dispatch.
    let functions = extract_functions(&language, &content);
    let mut matches: Vec<_> = functions.iter().filter(|f| f.name == function).collect();
    if let Some(at) = at_line {
        // Narrow to functions whose range encloses at_line. A missing line_end
        // (extractor couldn't compute it) requires an exact start match.
        matches.retain(|fi| match fi.line_end {
            Some(end) => fi.line_start <= at && at <= end,
            None => fi.line_start == at,
        });
    }
    let fi = *matches.first()?;

    let calls_made = filter_calls(&content, &language, fi.line_start, fi.line_end);
    let returns = walk_returns(&content, &language, fi.line_start, fi.line_end);
    let has_inline_asm = detect_inline_asm(&content, &language, fi.line_start, fi.line_end);

    // If line_end is None, fall back to start so the tuple stays valid.
    let end = fi.line_end.unwrap_or(fi.line_start);
    Some(FunctionView {
        function: fi.name.clone(),
        file: path.to_string_lossy().into_owned(),
        language,
        lines: (fi.line_start, end),
        signature: fi.signature.clone().unwrap_or_default(),
        calls_made,
        returns,
        has_inline_asm,
        schema_version: SCHEMA_VERSION,
    })
}

// ---------------------------------------------------------------------------
// Calls — line-range filter over the file-wide call graph
// ---------------------------------------------------------------------------

/// Return calls inside the function's line range. Empty when the language has no
/// call-graph walker. `typescript` routes through the JavaScript walker, exactly
/// as the Python dispatch table does.
fn filter_calls(
    content: &str,
    language: &str,
    line_start: i64,
    line_end: Option<i64>,
) -> Vec<CallSite> {
    let graph = match language {
        "python" => extract_call_graph_python(content),
        "javascript" | "typescript" => extract_call_graph_javascript(content),
        "java" => extract_call_graph_java(content),
        "go" => extract_call_graph_go(content),
        "c" => extract_call_graph_c(content),
        "cpp" => extract_call_graph_cpp(content),
        "rust" => extract_call_graph_rust(content),
        "ruby" => extract_call_graph_ruby(content),
        "csharp" => extract_call_graph_csharp(content),
        "php" => extract_call_graph_php(content),
        _ => return Vec::new(),
    };
    match line_end {
        // No upper bound known; return every call (best-effort), like Python.
        None => graph.calls,
        Some(end) => graph
            .calls
            .into_iter()
            .filter(|c| line_start <= c.line && c.line <= end)
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Returns
// ---------------------------------------------------------------------------

/// Return all explicit `return` statements inside the function. Implicit returns
/// are NOT emitted. Only Python + {C, C++, JavaScript, Java, Go} produce returns
/// (the set for which the Python `_ts_grammar_module` hands out a grammar);
/// `typescript` uses the JavaScript grammar, matching Python.
fn walk_returns(content: &str, language: &str, line_start: i64, line_end: Option<i64>) -> Vec<Return> {
    let Some(end) = line_end else {
        return Vec::new();
    };
    if language == "python" {
        return walk_returns_python(content, line_start, end);
    }
    let grammar_lang = match language {
        "c" => "c",
        "cpp" => "cpp",
        "javascript" | "typescript" => "javascript",
        "java" => "java",
        "go" => "go",
        _ => return Vec::new(),
    };
    walk_returns_ts(content, grammar_lang, line_start, end)
}

/// Byte-offset → 1-based line index (counts `\n`, so `\n` and `\r\n` both
/// resolve). Mirrors inventory's `PyLineIndex` (which is crate-private).
struct LineIndex {
    line_starts: Vec<usize>,
}

impl LineIndex {
    fn new(src: &str) -> Self {
        let mut line_starts = vec![0usize];
        for (i, b) in src.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    fn line_of(&self, offset: usize) -> i64 {
        self.line_starts.partition_point(|&s| s <= offset) as i64
    }
}

/// Walk the whole file's Python AST (rustpython), collect every explicit
/// `return`, filter to `[line_start, line_end]`, and sort by line — matching the
/// Python `_walk_returns_python`, which walks the entire tree then sorts because
/// `ast.walk` order is not source order.
///
/// `value_text` is the source slice of the returned expression (the closest
/// faithful stand-in for CPython `ast.unparse(node.value)`; identical for
/// canonically-formatted code). It is not asserted by the parity oracle.
fn walk_returns_python(content: &str, line_start: i64, line_end: i64) -> Vec<Return> {
    use rustpython_parser::ast::Suite;
    use rustpython_parser::Parse as _;

    let body = match Suite::parse(content, "<core.ast.view>") {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let idx = LineIndex::new(content);
    let mut out: Vec<Return> = Vec::new();
    collect_returns_py(&body, content, &idx, &mut out);
    out.retain(|r| line_start <= r.line && r.line <= line_end);
    out.sort_by_key(|r| r.line);
    out
}

fn collect_returns_py(
    stmts: &[rustpython_parser::ast::Stmt],
    content: &str,
    idx: &LineIndex,
    out: &mut Vec<Return>,
) {
    use rustpython_parser::ast::{ExceptHandler, Stmt};
    for s in stmts {
        match s {
            Stmt::Return(n) => {
                let start = n.range.start().to_usize();
                let line = idx.line_of(start);
                let value_text = match &n.value {
                    Some(_) => {
                        let end = n.range.end().to_usize();
                        let full = content.get(start..end).unwrap_or("");
                        // Strip the leading `return` keyword, then trim.
                        full.strip_prefix("return").unwrap_or(full).trim().to_string()
                    }
                    None => String::new(),
                };
                out.push(Return { line, value_text });
            }
            Stmt::FunctionDef(n) => collect_returns_py(&n.body, content, idx, out),
            Stmt::AsyncFunctionDef(n) => collect_returns_py(&n.body, content, idx, out),
            Stmt::ClassDef(n) => collect_returns_py(&n.body, content, idx, out),
            Stmt::If(n) => {
                collect_returns_py(&n.body, content, idx, out);
                collect_returns_py(&n.orelse, content, idx, out);
            }
            Stmt::For(n) => {
                collect_returns_py(&n.body, content, idx, out);
                collect_returns_py(&n.orelse, content, idx, out);
            }
            Stmt::AsyncFor(n) => {
                collect_returns_py(&n.body, content, idx, out);
                collect_returns_py(&n.orelse, content, idx, out);
            }
            Stmt::While(n) => {
                collect_returns_py(&n.body, content, idx, out);
                collect_returns_py(&n.orelse, content, idx, out);
            }
            Stmt::With(n) => collect_returns_py(&n.body, content, idx, out),
            Stmt::AsyncWith(n) => collect_returns_py(&n.body, content, idx, out),
            Stmt::Match(n) => {
                for case in &n.cases {
                    collect_returns_py(&case.body, content, idx, out);
                }
            }
            Stmt::Try(n) => {
                collect_returns_py(&n.body, content, idx, out);
                for h in &n.handlers {
                    let ExceptHandler::ExceptHandler(eh) = h;
                    collect_returns_py(&eh.body, content, idx, out);
                }
                collect_returns_py(&n.orelse, content, idx, out);
                collect_returns_py(&n.finalbody, content, idx, out);
            }
            Stmt::TryStar(n) => {
                collect_returns_py(&n.body, content, idx, out);
                for h in &n.handlers {
                    let ExceptHandler::ExceptHandler(eh) = h;
                    collect_returns_py(&eh.body, content, idx, out);
                }
                collect_returns_py(&n.orelse, content, idx, out);
                collect_returns_py(&n.finalbody, content, idx, out);
            }
            _ => {}
        }
    }
}

/// Generic tree-sitter `return_statement` walk. `value_text` is the text of the
/// first named child (empty for a bare `return`), matching the Python
/// `_walk_returns_ts`.
fn walk_returns_ts(content: &str, grammar_lang: &str, line_start: i64, line_end: i64) -> Vec<Return> {
    let Some(tree) = mantishack_ts::parse(grammar_lang, content) else {
        return Vec::new();
    };
    let src = content.as_bytes();
    let mut out: Vec<Return> = Vec::new();
    visit_ts(tree.root_node(), src, line_start, line_end, &mut out);
    out
}

fn visit_ts(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    line_start: i64,
    line_end: i64,
    out: &mut Vec<Return>,
) {
    // Cheap line-range prune: skip subtrees entirely outside the window.
    let n_start = node.start_position().row as i64 + 1;
    let n_end = node.end_position().row as i64 + 1;
    if n_start > line_end || n_end < line_start {
        return;
    }
    if node.kind() == "return_statement" {
        let line = n_start;
        if line_start <= line && line <= line_end {
            let mut value_text = String::new();
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.is_named() {
                    value_text = child.utf8_text(src).unwrap_or("").to_string();
                    break;
                }
            }
            out.push(Return { line, value_text });
        }
        // Still descend so nested functions / lambdas inside the return
        // expression are seen (matches Python).
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_ts(child, src, line_start, line_end, out);
    }
}

// ---------------------------------------------------------------------------
// Inline asm (C/C++ only)
// ---------------------------------------------------------------------------

/// Whole-word match for the three GNU-extension asm keywords, matching the
/// Python `_ASM_PATTERN`.
fn asm_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(__asm__|__asm|asm)\b\s*(?:volatile|goto)?\s*[(]").unwrap())
}

/// True iff a GNU inline-asm construct appears in the function body. Non-C/C++
/// always false.
fn detect_inline_asm(content: &str, language: &str, line_start: i64, line_end: Option<i64>) -> bool {
    if language != "c" && language != "cpp" {
        return false;
    }
    let Some(end) = line_end else {
        return false;
    };
    // Slice the body by lines (1-indexed), matching `"\n".join(lines[start-1:end])`.
    let lines = splitlines(content);
    let start_idx = (line_start - 1).max(0) as usize;
    let end_idx = (end.max(0) as usize).min(lines.len());
    if start_idx >= end_idx {
        return false;
    }
    let body = lines[start_idx..end_idx].join("\n");
    asm_pattern().is_match(&body)
}

/// Split like Python `str.splitlines()` for the common source-code line endings
/// (`\n`, `\r`, `\r\n`) with no trailing empty element.
fn splitlines(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                out.push(&s[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                out.push(&s[start..i]);
                if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                    i += 2;
                } else {
                    i += 1;
                }
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < bytes.len() {
        out.push(&s[start..]);
    }
    out
}

// ---------------------------------------------------------------------------
// Tests — golden vectors mirroring core/ast/tests/test_view.py
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Fixture contents are embedded verbatim (line numbers must match the
    // on-disk fixtures in core/ast/tests/fixtures/ exactly).
    const SAMPLE_C: &str = r#"#include <stdio.h>
#include "internal.h"

static int helper(int x) {
    return x + 1;
}

int main(int argc, char **argv) {
    asm volatile ("nop");
    if (helper(argc) > 0) {
        printf("positive");
        return 0;
    }
    return 1;
}
"#;

    const SAMPLE_CPP: &str = r#"#include <iostream>

class Widget {
public:
    void setup();
    int run(int x);
    ~Widget();
private:
    int counter_;
};

void Widget::setup() {
    counter_ = 0;
    helper();
}

int Widget::run(int x) {
    this->setup();
    if (x > 0) {
        return x * 2;
    }
    return 0;
}

Widget::~Widget() {
    cleanup();
}
"#;

    const SAMPLE_PY: &str = r#"# ruff: noqa: F821
# Fixture file: deliberately references undefined names
# (``compute_hash``, ``log_attempt``, ``constant_time_compare``)
# so the view() tests have realistic call-site shapes without
# pulling in real implementations.

def check_password(user, pw):
    """Check whether `pw` matches `user`'s hash."""
    if user is None:
        return -1
    hashed = compute_hash(pw)
    log_attempt(user)
    if constant_time_compare(user.pw_hash, hashed):
        return 0
    return 1


class Auth:
    def login(self, user, pw):
        return check_password(user, pw)

    def logout(self, user):
        pass
"#;

    const SAMPLE_GO: &str = r#"package main

import "fmt"

func helper(x int) int {
    return x + 1
}

func main() {
    if helper(3) > 0 {
        fmt.Println("ok")
        return
    }
    fmt.Println("nope")
}
"#;

    fn write_fixture(name: &str, content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(name);
        std::fs::write(&p, content).unwrap();
        (dir, p)
    }

    // ---- C ----

    #[test]
    fn c_main_view() {
        let (_d, p) = write_fixture("sample.c", SAMPLE_C);
        let fv = view(&p, "main", None, None).expect("main view");
        assert_eq!(fv.function, "main");
        assert_eq!(fv.language, "c");
        assert!(fv.calls_made.iter().any(|c| c.chain == ["helper"]));
        assert!(fv.calls_made.iter().any(|c| c.chain == ["printf"]));
        let mut return_lines: Vec<i64> = fv.returns.iter().map(|r| r.line).collect();
        return_lines.sort_unstable();
        assert_eq!(return_lines.len(), 2);
        assert!(fv.has_inline_asm);
    }

    #[test]
    fn c_helper_view_no_asm() {
        let (_d, p) = write_fixture("sample.c", SAMPLE_C);
        let fv = view(&p, "helper", None, None).expect("helper view");
        assert!(!fv.has_inline_asm);
        assert_eq!(fv.returns.len(), 1);
        assert_eq!(fv.returns[0].value_text, "x + 1");
        assert!(fv.calls_made.is_empty());
    }

    // ---- C++ ----
    //
    // KNOWN DEPENDENCY GAP (not a bug in this crate): C++ *out-of-line* method
    // definitions (`void Widget::setup() {…}`, `Widget::~Widget() {…}`) are not
    // discovered because `mantishack_core_inventory::ts_extract::get_name` has no
    // case for the tree-sitter-cpp `qualified_identifier` / `destructor_name`
    // declarators, so `extract_functions("cpp", …)` returns an empty list and
    // `view()` therefore returns None. The Python oracle handles these (its
    // `TreeSitterExtractor._get_name` was fixed for qualified+destructor
    // declarators); the fix is not yet ported into the inventory crate, which is
    // outside this port's scope. The C++ *call graph* is fully ported and correct
    // (asserted below), so the gap is isolated to function discovery. When
    // inventory learns those declarators, replace the `is_none()` canaries with
    // the full parity assertions preserved in comments.

    #[test]
    fn cpp_call_graph_is_correct() {
        // The call-graph half of the composition works for C++: `this->setup()`
        // is tagged receiver_class="Widget", `helper()`/`cleanup()` are free
        // calls. This is what `view().calls_made` would carry once inventory can
        // discover the enclosing out-of-line methods.
        let g = extract_call_graph_cpp(SAMPLE_CPP);
        let this_setup: Vec<&CallSite> =
            g.calls.iter().filter(|c| c.chain == ["this", "setup"]).collect();
        assert_eq!(this_setup.len(), 1);
        assert_eq!(this_setup[0].receiver_class.as_deref(), Some("Widget"));
        assert!(g
            .calls
            .iter()
            .any(|c| c.chain == ["helper"] && c.receiver_class.is_none()));
        assert!(g.calls.iter().any(|c| c.chain == ["cleanup"]));
    }

    #[test]
    fn cpp_out_of_line_methods_blocked_by_inventory_get_name_gap() {
        let (_d, p) = write_fixture("sample.cpp", SAMPLE_CPP);
        // detect_language works; the gap is purely function discovery.
        assert_eq!(detect_language("sample.cpp"), Some("cpp"));
        assert!(extract_functions("cpp", SAMPLE_CPP).is_empty());

        // Canaries: currently None. When inventory's get_name handles
        // qualified_identifier/destructor_name, these become Some and the
        // assertions below (the Python-oracle parity contract) should replace them.
        assert!(view(&p, "run", None, None).is_none());
        assert!(view(&p, "setup", None, None).is_none());
        assert!(view(&p, "~Widget", None, None).is_none());
        // Intended parity (test_view.py) once the dependency gap closes:
        //   run:     calls_made has ["this","setup"] with receiver_class "Widget";
        //            returns.len() == 2
        //   setup:   calls_made has ["helper"] with receiver_class None
        //   ~Widget: function == "~Widget"; calls_made has ["cleanup"]
    }

    // ---- Python ----

    #[test]
    fn py_check_password_view() {
        let (_d, p) = write_fixture("sample.py", SAMPLE_PY);
        let fv = view(&p, "check_password", None, None).expect("check_password view");
        assert_eq!(fv.language, "python");
        let names: Vec<String> = fv.calls_made.iter().map(|c| c.chain.join(".")).collect();
        assert!(names.iter().any(|n| n == "compute_hash"));
        assert!(names.iter().any(|n| n == "log_attempt"));
        assert!(names.iter().any(|n| n == "constant_time_compare"));
        let lines: Vec<i64> = fv.returns.iter().map(|r| r.line).collect();
        let mut sorted = lines.clone();
        sorted.sort_unstable();
        assert_eq!(lines, sorted, "returns must be in source order");
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn py_method_inside_class() {
        let (_d, p) = write_fixture("sample.py", SAMPLE_PY);
        let fv = view(&p, "login", None, None).expect("login view");
        assert!(fv.calls_made.iter().any(|c| c.chain == ["check_password"]));
    }

    #[test]
    fn py_no_inline_asm() {
        let (_d, p) = write_fixture("sample.py", SAMPLE_PY);
        let fv = view(&p, "check_password", None, None).expect("check_password view");
        assert!(!fv.has_inline_asm);
    }

    // ---- Go ----

    #[test]
    fn go_main_view() {
        let (_d, p) = write_fixture("sample.go", SAMPLE_GO);
        let fv = view(&p, "main", None, None).expect("main view");
        let println: Vec<&CallSite> = fv
            .calls_made
            .iter()
            .filter(|c| c.chain.last().map(|s| s.as_str()) == Some("Println"))
            .collect();
        assert!(!println.is_empty());
    }

    #[test]
    fn go_no_inline_asm() {
        let (_d, p) = write_fixture("sample.go", SAMPLE_GO);
        let fv = view(&p, "main", None, None).expect("main view");
        assert!(!fv.has_inline_asm);
    }

    // ---- Edge cases ----

    #[test]
    fn missing_file_returns_none() {
        assert!(view(Path::new("/no/such/file.c"), "foo", None, None).is_none());
    }

    #[test]
    fn unknown_extension_returns_none() {
        let (_d, p) = write_fixture("unknown.xyz", "whatever");
        assert!(view(&p, "foo", None, None).is_none());
    }

    #[test]
    fn function_not_found_returns_none() {
        let (_d, p) = write_fixture("x.c", "int main(void) { return 0; }\n");
        assert!(view(&p, "nonexistent", None, None).is_none());
        assert!(view(&p, "main", None, None).is_some());
    }

    #[test]
    fn language_override() {
        let (_d, p) = write_fixture("noext", "int main(void) { return 0; }\n");
        // Detection fails on a file with no extension.
        assert!(view(&p, "main", None, None).is_none());
        let fv = view(&p, "main", None, Some("c")).expect("override view");
        assert_eq!(fv.language, "c");
    }

    #[test]
    fn at_line_disambiguates_collision() {
        let src = "class A:\n    def __init__(self):\n        self.a = 1\nclass B:\n    def __init__(self):\n        self.b = 2\n";
        let (_d, p) = write_fixture("x.py", src);
        let fv = view(&p, "__init__", Some(5), None).expect("disambiguated view");
        assert!(fv.lines.0 <= 5 && 5 <= fv.lines.1);
    }

    // ---- Schema round-trip ----

    #[test]
    fn to_json_carries_full_schema() {
        let (_d, p) = write_fixture("sample.c", SAMPLE_C);
        let fv = view(&p, "main", None, None).expect("main view");
        let d = fv.to_json();
        let obj = d.as_object().expect("object");
        for key in [
            "function",
            "file",
            "language",
            "lines",
            "signature",
            "calls_made",
            "returns",
            "has_inline_asm",
            "schema_version",
        ] {
            assert!(obj.contains_key(key), "missing key {key}");
        }
        assert_eq!(obj["schema_version"], serde_json::json!(SCHEMA_VERSION));
        for c in obj["calls_made"].as_array().unwrap() {
            let cm = c.as_object().unwrap();
            for key in ["line", "chain", "caller", "receiver_class"] {
                assert!(cm.contains_key(key), "call missing key {key}");
            }
        }
        for r in obj["returns"].as_array().unwrap() {
            let rm = r.as_object().unwrap();
            assert_eq!(rm.len(), 2);
            assert!(rm.contains_key("line"));
            assert!(rm.contains_key("value_text"));
        }
    }

    #[test]
    fn to_json_is_json_serialisable() {
        let (_d, p) = write_fixture("sample.c", SAMPLE_C);
        let fv = view(&p, "main", None, None).expect("main view");
        let s = serde_json::to_string(&fv.to_json()).unwrap();
        let d: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(d["function"], serde_json::json!("main"));
    }
}
