//! Dataflow-validation data models + bitvector-profile inference.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

/// A single step in a dataflow path (`DataflowStep`).
#[derive(Clone, Debug, PartialEq)]
pub struct DataflowStep {
    pub file_path: String,
    pub line: i64,
    pub column: i64,
    pub snippet: String,
    pub label: String,
}

/// A complete dataflow path from source to sink (`DataflowPath`).
#[derive(Clone, Debug, PartialEq)]
pub struct DataflowPath {
    pub source: DataflowStep,
    pub sink: DataflowStep,
    pub intermediate_steps: Vec<DataflowStep>,
    pub sanitizers: Vec<String>,
    pub rule_id: String,
    pub message: String,
}

/// The result of dataflow validation (`DataflowValidation`).
#[derive(Clone, Debug, PartialEq)]
pub struct DataflowValidation {
    pub is_exploitable: bool,
    pub confidence: f64,
    pub sanitizers_effective: bool,
    pub bypass_possible: bool,
    pub bypass_strategy: Option<String>,
    pub attack_complexity: String,
    pub reasoning: String,
    pub barriers: Vec<String>,
    pub prerequisites: Vec<String>,
}

/// A bitvector profile for SMT path-condition encoding (`BVProfile`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BVProfile {
    pub width: i64,
    pub signed: bool,
}

/// Confidence reported alongside an SMT-infeasible verdict (`SMT_INFEASIBLE_CONFIDENCE`).
pub const SMT_INFEASIBLE_CONFIDENCE: f64 = 0.7;

fn overflow_markers_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)\b(",
            r"cwe-190|cwe-191|cwe-680|cwe-197|",
            r"int(?:eger)?[-_]?overflow|int(?:eger)?[-_]?underflow|",
            r"wrap(?:-?around)?|",
            r"signed[-_]?(?:overflow|underflow)",
            r")\b",
        ))
        .unwrap()
    })
}

/// Word-boundary check for an integer-overflow/underflow rule (`_is_overflow_rule`).
/// `buffer-overflow`/`stack-overflow`/`heap-overflow`/`cwe-1901` do NOT match.
pub fn is_overflow_rule(rule_id: &str) -> bool {
    overflow_markers_re().is_match(rule_id)
}

/// Build a `BVProfile` from the LLM's per-path hint, falling back to a rule-id
/// heuristic (`_infer_bv_profile`). Width is accepted only when it's a real
/// integer in {8,16,32,64} (bools/floats/out-of-range fall back to heuristic).
pub fn infer_bv_profile(rule_id: Option<&str>, llm_hint: &Value) -> BVProfile {
    let heuristic_width = if is_overflow_rule(rule_id.unwrap_or("")) { 32 } else { 64 };
    let heuristic_signed = false;

    // as_i64 is None for bools and floats, so those correctly fall back.
    let width = llm_hint
        .get("width")
        .and_then(Value::as_i64)
        .filter(|w| matches!(w, 8 | 16 | 32 | 64))
        .unwrap_or(heuristic_width);

    let signed = llm_hint.get("signed").and_then(Value::as_bool).unwrap_or(heuristic_signed);

    BVProfile { width, signed }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn overflow_rule_detection() {
        for (r, want) in [
            ("cpp/cwe-190", true), ("cpp/buffer-overflow", false), ("cpp/cwe-1901", false),
            ("cpp/integer-overflow", true), ("cpp/int_underflow", true), ("cpp/wraparound", true),
            ("cpp/signed-overflow", true), ("cpp/heap-overflow", false), ("cwe-680", true),
        ] {
            assert_eq!(is_overflow_rule(r), want, "{r}");
        }
    }

    #[test]
    fn bv_profile_inference() {
        assert_eq!(infer_bv_profile(Some("cpp/cwe-190"), &json!({})), BVProfile { width: 32, signed: false });
        assert_eq!(infer_bv_profile(Some("cpp/xss"), &json!({})), BVProfile { width: 64, signed: false });
        assert_eq!(infer_bv_profile(Some("cpp/xss"), &json!({"width": 32, "signed": true})), BVProfile { width: 32, signed: true });
        // Out-of-range / bool / float widths fall back to the heuristic.
        assert_eq!(infer_bv_profile(Some("cpp/cwe-190"), &json!({"width": 128})), BVProfile { width: 32, signed: false });
        assert_eq!(infer_bv_profile(Some("cpp/cwe-190"), &json!({"width": true})), BVProfile { width: 32, signed: false });
        assert_eq!(infer_bv_profile(Some("cpp/cwe-190"), &json!({"width": 32.0})), BVProfile { width: 32, signed: false });
    }
}
