//! Host-reachability dead-code classification — Rust port of
//! `packages/sca/reachability/_host_reachability.py`.
//!
//! Decides whether a vulnerable function's call sites all live in "dead" project
//! functions (no callers) so a finding can be downgraded to `called_in_dead_code`.
//! Drives the ported call-graph API in `mantishack_core_inventory`.

use mantishack_core_inventory::reachability::{
    callers_of, enclosing_function, parse_evidence_entry, reverse_closure, FunctionId,
    InternalFunction,
};
use mantishack_sca::{Confidence, Reachability};
use serde_json::Value;

// Conventional entry-point names — the language runtime invokes these, so they
// are always "alive" even with no static callers.
const ENTRY_POINT_NAMES: &[&str] = &["main", "_main", "__main__", "Main"];

// reverse_closure's Python default max_depth.
const REVERSE_CLOSURE_MAX_DEPTH: i64 = 50;

/// Heuristic: does this function name follow a private/internal convention
/// (`_looks_internal`)? True for a leading underscore.
pub fn looks_internal(name: &str) -> bool {
    !name.is_empty() && name.starts_with('_')
}

/// True iff `host` has no incoming call edges — neither a 1-hop caller nor a
/// transitive reverse-closure node (`is_host_dead`). Entry-point-named and
/// non-internally-named hosts are always treated as alive.
pub fn is_host_dead(inventory: &Value, host: &InternalFunction, exclude_test_files: bool) -> bool {
    if ENTRY_POINT_NAMES.contains(&host.name.as_str()) {
        return false;
    }
    if !looks_internal(&host.name) {
        return false;
    }
    let target = FunctionId::Internal(host.clone());
    let one_hop = callers_of(inventory, &target, exclude_test_files);
    if !one_hop.definitive.is_empty()
        || !one_hop.uncertain.is_empty()
        || !one_hop.method_match_overinclusive.is_empty()
    {
        return false; // has at least one caller
    }
    let transitive = reverse_closure(inventory, &target, REVERSE_CLOSURE_MAX_DEPTH, exclude_test_files);
    transitive.nodes.is_empty()
}

/// True iff EVERY parseable evidence entry resolves to an enclosing function
/// that `is_host_dead` (`all_call_sites_in_dead_code`). False on empty evidence,
/// any module-scope call site, or any live host.
pub fn all_call_sites_in_dead_code(
    inventory: &Value,
    evidence: &[String],
    exclude_test_files: bool,
) -> bool {
    if evidence.is_empty() {
        return false;
    }
    let mut saw_evaluable = false;
    for entry in evidence {
        let (path, line) = parse_evidence_entry(entry);
        let Some(path) = path else { continue }; // unparseable -> skip
        let Some(host) = enclosing_function(inventory, &path, line) else {
            return false; // module-level call: runs at import time, NOT dead
        };
        saw_evaluable = true;
        if !is_host_dead(inventory, &host, exclude_test_files) {
            return false;
        }
    }
    saw_evaluable
}

/// Decide between `likely_called` and `called_in_dead_code` for a set of call
/// sites (`classify_called_or_dead`).
pub fn classify_called_or_dead(
    inventory: &Value,
    evidence_lines: &[String],
    likely_called_reason: &str,
    affected_summary: &str,
) -> Reachability {
    let evidence: Vec<String> = evidence_lines.iter().take(5).cloned().collect();
    if all_call_sites_in_dead_code(inventory, evidence_lines, true) {
        Reachability {
            verdict: "called_in_dead_code".to_string(),
            confidence: Confidence::new(
                "medium",
                &format!(
                    "{affected_summary} called only from project functions with no internal callers \u{2014} likely dead code, but host may be an unseen entry point (CLI / framework / fixture); confidence medium accordingly"
                ),
            ),
            evidence,
        }
    } else {
        Reachability {
            verdict: "likely_called".to_string(),
            confidence: Confidence::new("high", likely_called_reason),
            evidence,
        }
    }
}

/// Pull affected-function names out of an OSV advisory's `ecosystem_specific` /
/// `database_specific` blocks (`_extract_function_names`). Tries the
/// `imports[].symbols` shape then the flat `affected_symbols` /
/// `affected_functions` lists, in that order, WITHOUT deduplication.
pub fn extract_osv_function_names(advisory: &Value) -> Vec<String> {
    let es = advisory.get("ecosystem_specific").and_then(Value::as_object);
    let ds = advisory.get("database_specific").and_then(Value::as_object);
    let sources = [es, ds];

    let mut out = Vec::new();
    for source in sources.into_iter().flatten() {
        if let Some(imports) = source.get("imports").and_then(Value::as_array) {
            for imp in imports {
                if let Some(syms) = imp.get("symbols").and_then(Value::as_array) {
                    out.extend(syms.iter().filter_map(|s| s.as_str().map(str::to_string)));
                }
            }
        }
    }
    for key in ["affected_symbols", "affected_functions"] {
        for source in sources.into_iter().flatten() {
            if let Some(v) = source.get(key).and_then(Value::as_array) {
                out.extend(v.iter().filter_map(|s| s.as_str().map(str::to_string)));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // One internally-named orphan function with no callers -> dead.
    fn inv() -> Value {
        json!({"files": [{"path": "a.py", "language": "python",
            "items": [
                {"name": "_orphan", "line_start": 10, "line_end": 20, "kind": "function"},
                {"name": "live", "line_start": 30, "line_end": 40, "kind": "function"},
                {"name": "caller", "line_start": 50, "line_end": 60, "kind": "function"},
            ],
            "call_graph": {"imports": {}, "calls": [
                {"chain": ["live"], "line": 55, "caller": "caller"}
            ]}}]})
    }

    #[test]
    fn looks_internal_heuristic() {
        assert!(looks_internal("_helper"));
        assert!(looks_internal("__x"));
        assert!(!looks_internal("public"));
        assert!(!looks_internal(""));
    }

    #[test]
    fn host_dead_short_circuits_and_orphan() {
        // Entry-point name -> alive.
        assert!(!is_host_dead(&inv(), &InternalFunction::new("a.py", "main", 1), true));
        // Non-internal name -> alive.
        assert!(!is_host_dead(&inv(), &InternalFunction::new("a.py", "live", 30), true));
        // Internally-named orphan with no callers -> dead.
        assert!(is_host_dead(&inv(), &InternalFunction::new("a.py", "_orphan", 10), true));
    }

    #[test]
    fn all_call_sites_and_classify() {
        // Empty evidence -> false.
        assert!(!all_call_sites_in_dead_code(&inv(), &[], true));
        // Module-level evidence (line 1, no enclosing fn) -> false.
        assert!(!all_call_sites_in_dead_code(&inv(), &["a.py:1".into()], true));
        // Evidence inside the dead orphan -> true.
        assert!(all_call_sites_in_dead_code(&inv(), &["a.py:15".into()], true));
        // Evidence inside a live function -> false.
        assert!(!all_call_sites_in_dead_code(&inv(), &["a.py:35".into()], true));

        // classify: dead-code path.
        let r = classify_called_or_dead(&inv(), &["a.py:15".into()], "reachable via X", "func foo()");
        assert_eq!(r.verdict, "called_in_dead_code");
        assert_eq!(r.confidence.level, "medium");
        assert!(r.confidence.reason.starts_with("func foo() called only from project functions with no internal callers"));
        assert_eq!(r.evidence, vec!["a.py:15".to_string()]);

        // classify: likely-called path (module-level evidence).
        let r = classify_called_or_dead(&inv(), &["a.py:1".into()], "reachable via X", "func foo()");
        assert_eq!(r.verdict, "likely_called");
        assert_eq!(r.confidence.level, "high");
        assert_eq!(r.confidence.reason, "reachable via X");

        // Evidence truncated to first 5.
        let many: Vec<String> = (0..8).map(|i| format!("a.py:{i}")).collect();
        let r = classify_called_or_dead(&inv(), &many, "reachable via X", "foo");
        assert_eq!(r.evidence.len(), 5);
    }

    #[test]
    fn osv_function_name_extraction() {
        assert_eq!(
            extract_osv_function_names(&json!({"ecosystem_specific": {"imports": [{"symbols": ["foo", "bar"]}, {"symbols": ["baz"]}]}})),
            vec!["foo", "bar", "baz"]
        );
        assert_eq!(
            extract_osv_function_names(&json!({"database_specific": {"affected_symbols": ["a", "b"], "affected_functions": ["c"]}})),
            vec!["a", "b", "c"]
        );
        assert_eq!(
            extract_osv_function_names(&json!({"ecosystem_specific": {"imports": [{"symbols": ["x"]}]}, "database_specific": {"affected_functions": ["y"]}})),
            vec!["x", "y"]
        );
        // Duplicates are NOT collapsed (mirrors the Python code, not its docstring).
        assert_eq!(
            extract_osv_function_names(&json!({"ecosystem_specific": {"affected_symbols": ["dup"]}, "database_specific": {"affected_symbols": ["dup"]}})),
            vec!["dup", "dup"]
        );
        assert!(extract_osv_function_names(&json!({})).is_empty());
        // Non-string entries skipped.
        assert_eq!(
            extract_osv_function_names(&json!({"ecosystem_specific": {"imports": [{"symbols": ["ok", 123, null]}], "affected_functions": ["z", 5]}})),
            vec!["ok", "z"]
        );
    }
}
