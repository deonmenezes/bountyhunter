//! Convert Coccinelle results to MANTISHACK findings format — faithful port of
//! `packages/coccinelle/findings.py::to_findings`.

use serde_json::{json, Value};
use std::collections::HashMap;

use crate::models::SpatchResult;

/// Convert spatch results to MANTISHACK `findings.json` entries.
///
/// Each match becomes a finding with origin `coccinelle` and vuln_type
/// `inconsistency`. Per-rule counters increment in encounter order, so two
/// `SpatchResult`s for the same rule keep producing unique, monotonic ids.
pub fn to_findings(results: &[SpatchResult]) -> Vec<Value> {
    let mut findings: Vec<Value> = Vec::new();
    let mut counters: HashMap<&str, i64> = HashMap::new();
    for result in results {
        for m in &result.matches {
            let c = counters.entry(result.rule.as_str()).or_insert(0);
            *c += 1;
            let description = if m.message.is_empty() {
                format!("Inconsistency detected by {}", result.rule)
            } else {
                m.message.clone()
            };
            findings.push(json!({
                "id": format!("COCCI-{}-{}", result.rule, *c),
                "file": m.file,
                "line": m.line,
                "function": "",
                "vuln_type": "inconsistency",
                "confidence": "medium",
                "origin": "coccinelle",
                "rule": result.rule,
                "description": description,
            }));
        }
    }
    findings
}
