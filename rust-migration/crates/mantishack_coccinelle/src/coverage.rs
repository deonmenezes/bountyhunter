//! Coverage record builder for Coccinelle — faithful port of
//! `packages/coccinelle/coverage.py::to_coverage_record`.
//!
//! Python stamps the record with `datetime.now(timezone.utc).isoformat()`; that
//! wall-clock read is the caller's concern here, so the timestamp is injected
//! (the PyO3 shim supplies `datetime.now(...).isoformat()` to stay byte-identical).

use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

use crate::models::SpatchResult;

/// Build a `coverage-coccinelle.json` record from spatch results, or `None` if
/// no files were examined.
pub fn to_coverage_record(results: &[SpatchResult], timestamp: &str) -> Option<Value> {
    // BTreeSet gives the dedup + lexicographic `sorted(files)` in one step.
    let mut files: BTreeSet<String> = BTreeSet::new();
    let mut rules: Vec<String> = Vec::new();
    let mut failures: Vec<Value> = Vec::new();

    for r in results {
        for f in &r.files_examined {
            files.insert(f.clone());
        }
        if !r.rule.is_empty() {
            rules.push(r.rule.clone());
        }
        for err in &r.errors {
            failures.push(json!({"rule": r.rule, "reason": err}));
        }
    }

    if files.is_empty() {
        return None;
    }

    let mut record = Map::new();
    record.insert("tool".into(), json!("coccinelle"));
    record.insert("timestamp".into(), json!(timestamp));
    record.insert(
        "files_examined".into(),
        json!(files.into_iter().collect::<Vec<_>>()),
    );
    if !rules.is_empty() {
        // dict.fromkeys(rules): dedupe preserving first-occurrence order.
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut applied: Vec<String> = Vec::new();
        for r in &rules {
            if seen.insert(r.as_str()) {
                applied.push(r.clone());
            }
        }
        record.insert("rules_applied".into(), json!(applied));
    }
    if !failures.is_empty() {
        record.insert("files_failed".into(), Value::Array(failures));
    }

    Some(Value::Object(record))
}
