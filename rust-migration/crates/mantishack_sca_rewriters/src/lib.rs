//! Manifest version-pin rewriters — Rust port of `packages/sca/rewriters/`.
//!
//! The shared `RewriteEdit` / `RewriteResult` records and each rewriter's pure
//! content→(new_content, results) transform port here. The atomic file
//! read/write wrapper (`rewrite(path, edits)` dispatch + `_atomic_write`) stays
//! call-site in Python and drives these text functions.

use serde_json::Value;

pub mod dockerfile_arg;
pub mod dockerfile_from;
pub mod dockerfile_inline_install;

pub use dockerfile_arg::rewrite_dockerfile_arg_text;
pub use dockerfile_from::{rewrite_dockerfile_from_text, route_kind};
pub use dockerfile_inline_install::rewrite_dockerfile_inline_install_text;

/// A single proposed edit to a manifest file (`RewriteEdit`). `locator`
/// identifies WHAT to edit (semantics are rewriter-specific); `extra` is a
/// kind-specific metadata escape-hatch (e.g. GHA SHA pins).
#[derive(Clone, Debug, PartialEq)]
pub struct RewriteEdit {
    pub locator: String,
    pub old_value: String,
    pub new_value: String,
    pub extra: Option<Value>,
}

impl RewriteEdit {
    pub fn new(locator: &str, old_value: &str, new_value: &str) -> Self {
        Self {
            locator: locator.to_string(),
            old_value: old_value.to_string(),
            new_value: new_value.to_string(),
            extra: None,
        }
    }
}

/// Per-edit outcome from a rewriter (`RewriteResult`).
#[derive(Clone, Debug, PartialEq)]
pub struct RewriteResult {
    pub edit: RewriteEdit,
    pub applied: bool,
    pub reason: String,
}

impl RewriteResult {
    pub fn new(edit: RewriteEdit, applied: bool, reason: &str) -> Self {
        Self { edit, applied, reason: reason.to_string() }
    }
}

/// CPython `repr()` for a `str` over the printable/common-escape range — used to
/// reproduce `{value!r}` interpolation in rewriter reason strings byte-for-byte.
pub(crate) fn py_repr(s: &str) -> String {
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}
