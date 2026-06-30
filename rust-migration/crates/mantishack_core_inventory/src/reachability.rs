//! Reachability resolver — Rust port of `core/inventory/reachability.py`
//! (IN PROGRESS).
//!
//! Started with the `Verdict` enum and the pure dict-reading accessors that the
//! `reach_audit` harness consumes (`module_aborts_on_load`, `build_excluded`,
//! `is_lexically_dead`). The full resolver — `function_called`, the adjacency
//! index (`_get_or_build_index`), entry-reachability, and the closures — is a
//! large graph-algorithm layer ported incrementally on top of this foundation.
//!
//! Accessors operate on the inventory as a `serde_json::Value`, matching the
//! Python `Dict[str, Any]` shape produced by the builder.

use serde_json::Value;

/// Reachability verdict for a queried qualified name (`Verdict`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Called,
    NotCalled,
    Uncertain,
}

impl Verdict {
    /// The lowercase string form, matching the Python `str` enum values.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Called => "called",
            Verdict::NotCalled => "not_called",
            Verdict::Uncertain => "uncertain",
        }
    }
}

fn norm(p: &str) -> String {
    p.replace('\\', "/")
}

/// First file record whose (slash-normalised) `path` equals `file_path`.
fn find_file<'a>(inventory: &'a Value, file_path: &str) -> Option<&'a Value> {
    let target = norm(file_path);
    inventory.get("files")?.as_array()?.iter().find(|fr| {
        fr.get("path").and_then(Value::as_str).map(norm).as_deref() == Some(target.as_str())
    })
}

/// The module-load-abort record for `file_path` (with `line`/`summary`) if the
/// builder detected an unconditional top-of-module abort, else `None`.
/// Path-keyed lookup, no index build.
pub fn module_aborts_on_load(inventory: &Value, file_path: &str) -> Option<Value> {
    if file_path.is_empty() {
        return None;
    }
    let fr = find_file(inventory, file_path)?;
    match fr.get("module_aborts_on_load") {
        Some(v) if v.is_object() => Some(v.clone()),
        _ => None,
    }
}

/// The build-exclusion record for `file_path` if the builder detected the file
/// is never compiled (e.g. Go `//go:build ignore`), else `None`.
pub fn build_excluded(inventory: &Value, file_path: &str) -> Option<Value> {
    if file_path.is_empty() {
        return None;
    }
    let fr = find_file(inventory, file_path)?;
    match fr.get("build_excluded") {
        Some(v) if v.is_object() => Some(v.clone()),
        _ => None,
    }
}

/// True iff `name` (at `line`, when `line > 0`) is defined inside a lexically
/// dead scope (`lexical_dead=True` on the item). With `line == 0`, matches by
/// name within the file (first hit wins). False-negative-safe: returns `false`
/// when the file or function isn't found.
pub fn is_lexically_dead(inventory: &Value, file_path: &str, name: &str, line: i64) -> bool {
    if file_path.is_empty() || name.is_empty() {
        return false;
    }
    let Some(fr) = find_file(inventory, file_path) else { return false };
    let Some(items) = fr.get("items").and_then(Value::as_array) else { return false };
    for item in items {
        if item.get("name").and_then(Value::as_str) != Some(name) {
            continue;
        }
        if line != 0 && item.get("line_start").and_then(Value::as_i64) != Some(line) {
            continue;
        }
        return item.get("lexical_dead").and_then(Value::as_bool).unwrap_or(false);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inv() -> Value {
        json!({
            "files": [
                {
                    "path": "src/a.py",
                    "module_aborts_on_load": {"line": 2, "summary": "raise ImportError"},
                    "items": [
                        {"name": "dead_fn", "line_start": 4, "lexical_dead": true},
                        {"name": "live_fn", "line_start": 8},
                    ],
                },
                {
                    "path": "pkg\\b.go",
                    "build_excluded": {"line": 1, "summary": "//go:build ignore"},
                    "items": [],
                },
            ]
        })
    }

    #[test]
    fn verdict_strings() {
        assert_eq!(Verdict::Called.as_str(), "called");
        assert_eq!(Verdict::NotCalled.as_str(), "not_called");
        assert_eq!(Verdict::Uncertain.as_str(), "uncertain");
    }

    #[test]
    fn module_aborts_lookup() {
        let i = inv();
        assert_eq!(module_aborts_on_load(&i, "src/a.py").unwrap()["summary"], json!("raise ImportError"));
        assert_eq!(module_aborts_on_load(&i, "pkg/b.go"), None);
        assert_eq!(module_aborts_on_load(&i, "missing.py"), None);
        assert_eq!(module_aborts_on_load(&i, ""), None);
    }

    #[test]
    fn build_excluded_lookup_normalises_backslash() {
        let i = inv();
        // Stored path uses a backslash; query with forward slash matches.
        assert_eq!(build_excluded(&i, "pkg/b.go").unwrap()["summary"], json!("//go:build ignore"));
        assert_eq!(build_excluded(&i, "src/a.py"), None);
    }

    #[test]
    fn lexical_dead_exact_and_name_only() {
        let i = inv();
        assert!(is_lexically_dead(&i, "src/a.py", "dead_fn", 4));
        assert!(is_lexically_dead(&i, "src/a.py", "dead_fn", 0)); // name-only
        assert!(!is_lexically_dead(&i, "src/a.py", "dead_fn", 99)); // wrong line
        assert!(!is_lexically_dead(&i, "src/a.py", "live_fn", 8));
        assert!(!is_lexically_dead(&i, "src/a.py", "ghost", 0));
        assert!(!is_lexically_dead(&i, "nope.py", "dead_fn", 4));
    }
}
