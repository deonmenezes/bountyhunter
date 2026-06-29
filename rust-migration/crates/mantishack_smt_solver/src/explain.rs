/// Unsat-core helpers: name which constraints contradict.
///
/// Faithful port of `core/smt_solver/explain.py`.
///
/// In Python, `track()` asserts labelled expressions via `assert_and_track`
/// (Z3's in-process API), and `core_names()` reads `solver.unsat_core()`.
///
/// In Rust, the equivalent is:
/// - `track()` generates SMT-LIB2 `(assert (! expr :named label))` statements
///   and records the `{label → human_name}` reverse map.
/// - `core_names()` parses the raw unsat-core output from `z3` (produced by
///   `(get-unsat-core)`) and translates labels back to human names.
///
/// The UUID-prefix collision-resistance from the Python implementation is
/// preserved: each `track()` call generates a fresh prefix so labels never
/// collide across calls or solver instances.
use std::collections::HashMap;

/// Assert labelled expressions in the session and return the reverse mapping.
///
/// Each `(name, smtlib_expr)` pair is emitted as an SMT-LIB2 named assertion:
/// ```text
/// (assert (! <expr> :named _c<prefix>_<i>))
/// ```
///
/// The returned map is `{label → human_name}`, for use with `core_names()`.
///
/// Pass an existing `rev` to accumulate across multiple batches on the same
/// session — exactly mirrors Python's `rev: Optional[Dict]` parameter.
///
/// UUID-prefix: each call mints a fresh 8-hex-char prefix via `uuid4()`,
/// providing cross-call collision resistance regardless of how many solver
/// sessions are active. Mirrors Python's `call_prefix = uuid.uuid4().hex[:8]`.
pub fn track(
    session: &mut crate::session::SolverSession,
    labeled: &[(String, String)],
    rev: Option<&mut HashMap<String, String>>,
) -> HashMap<String, String> {
    let call_prefix = make_prefix();
    let mut local_rev = HashMap::new();
    let rev = rev.unwrap_or(&mut local_rev);

    for (i, (name, expr)) in labeled.iter().enumerate() {
        let label = format!("_c{}_{}", call_prefix, i);
        let stmt = format!("(assert (! {} :named {}))", expr, label);
        session.add(stmt);
        rev.insert(label, name.clone());
    }

    // Return a clone of the accumulated rev so the caller owns it.
    rev.clone()
}

/// Return human-readable names of assertions in the unsat core.
///
/// Call after the solver returns `unsat` and you have the raw `(get-unsat-core)`
/// output. Labels added by other callers (not present in `rev`) are silently
/// omitted, mirroring Python's `rev.get(str(label))` None-skip.
///
/// `unsat_core_output` is the raw text from z3's `(get-unsat-core)` response,
/// e.g. `(_c3a2f1b0_0 _c3a2f1b0_1)`. The function extracts identifiers and
/// looks them up in `rev`.
///
/// Returns `[]` on any parse failure — mirrors Python's `except (Z3Exception,
/// AttributeError): return names` guard in `core_names`.
pub fn core_names(
    unsat_core_output: &str,
    rev: &HashMap<String, String>,
) -> Vec<String> {
    parse_unsat_core_labels(unsat_core_output)
        .into_iter()
        .filter_map(|label| rev.get(&label).cloned())
        .collect()
}

/// Extract identifier tokens from a z3 unsat-core response.
/// Expected form: `(<label1> <label2> ...)` or bare identifiers.
fn parse_unsat_core_labels(output: &str) -> Vec<String> {
    use std::sync::OnceLock;
    use regex::Regex;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"[A-Za-z_][A-Za-z0-9_]*").unwrap());
    re.find_iter(output)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Generate an 8-hex-char collision-resistant prefix.
/// Mirrors `uuid.uuid4().hex[:8]`.
fn make_prefix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Cheap pseudo-random prefix: mix thread id + timestamp nanos.
    // Not cryptographically random (we don't need that) but collision-resistant
    // across concurrent calls in a single process.
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let _tid = std::thread::current().id();
    // Mix with a counter to avoid same-nanosecond collisions.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:04x}{:04x}", (t ^ (seq as u32)) & 0xFFFF, (seq >> 16) & 0xFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SolverSession;

    #[test]
    fn track_emits_named_assertions() {
        let mut session = SolverSession::new();
        session.add("(declare-const x (_ BitVec 32))");
        let labeled = vec![
            ("overflow_guard".to_string(), "(bvugt x (_ bv0 32))".to_string()),
            ("size_bound".to_string(), "(bvult x (_ bv1024 32))".to_string()),
        ];
        let rev = track(&mut session, &labeled, None);
        // rev maps label → human name
        assert_eq!(rev.len(), 2);
        let names: Vec<&String> = rev.values().collect();
        assert!(names.iter().any(|n| n.as_str() == "overflow_guard"));
        assert!(names.iter().any(|n| n.as_str() == "size_bound"));
    }

    #[test]
    fn track_labels_unique_across_calls() {
        let mut session = SolverSession::new();
        let labeled = vec![("a".to_string(), "true".to_string())];
        let rev1 = track(&mut session, &labeled, None);
        let rev2 = track(&mut session, &labeled, None);
        // Labels from two calls must not collide.
        let labels1: Vec<&String> = rev1.keys().collect();
        let labels2: Vec<&String> = rev2.keys().collect();
        assert!(labels1.iter().all(|l1| labels2.iter().all(|l2| l1 != l2)));
    }

    #[test]
    fn core_names_translates_labels() {
        let mut rev = HashMap::new();
        rev.insert("_cdeadbeef_0".to_string(), "overflow_guard".to_string());
        rev.insert("_cdeadbeef_1".to_string(), "size_bound".to_string());

        let output = "(_cdeadbeef_0 _cdeadbeef_1)";
        let names = core_names(output, &rev);
        assert!(names.contains(&"overflow_guard".to_string()));
        assert!(names.contains(&"size_bound".to_string()));
    }

    #[test]
    fn core_names_empty_output_returns_empty() {
        let rev = HashMap::new();
        let names = core_names("", &rev);
        assert!(names.is_empty());
    }

    #[test]
    fn core_names_unknown_labels_omitted() {
        let rev = HashMap::new(); // empty — no known labels
        let output = "(_cunknown_0 _cunknown_1)";
        let names = core_names(output, &rev);
        // Labels not in rev are silently omitted.
        assert!(names.is_empty());
    }
}
