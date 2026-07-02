//! Ground-truth labels for the dataflow corpus — Rust port of the pure model in
//! `core/dataflow/label.py`. Validation, `to_dict`/`from_dict`, and
//! `to_json`/`from_json` (byte-compatible with CPython `json.dumps`) port here.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::py_json;

pub const SCHEMA_VERSION: i64 = 1;

pub const VERDICT_TRUE_POSITIVE: &str = "true_positive";
pub const VERDICT_FALSE_POSITIVE: &str = "false_positive";

/// Sorted, like Python `sorted(VALID_VERDICTS)`.
const VALID_VERDICTS_SORTED: &[&str] = &["false_positive", "true_positive"];

/// Sorted, like Python `sorted(VALID_FP_CATEGORIES)`.
const VALID_FP_CATEGORIES_SORTED: &[&str] = &[
    "dead_code",
    "framework_mitigation",
    "infeasible_branch",
    "missing_sanitizer_model",
    "reflection_imprecision",
    "type_constraint",
];

const GROUND_TRUTH_KEYS: &[&str] = &[
    "schema_version", "finding_id", "verdict", "fp_category", "rationale", "labeler", "labeled_at",
    "lifecycle_precondition",
];

const LIFECYCLE_PRECONDITION_KEYS: &[&str] =
    &["field", "write_site_guard", "read_site_lacks_guard", "notes"];

fn iso_date_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap())
}

/// CPython `repr()` of a string (single-quote preferred).
fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::new();
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

/// `repr()` of a Python list of strings: `['a', 'b']`.
fn py_list_repr(items: &[&str]) -> String {
    let inner: Vec<String> = items.iter().map(|s| py_repr(s)).collect();
    format!("[{}]", inner.join(", "))
}

fn check_extra_fields(name: &str, data: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    let mut extras: Vec<&str> = data.keys().map(String::as_str).filter(|k| !allowed.contains(k)).collect();
    if !extras.is_empty() {
        extras.sort();
        return Err(format!("unknown fields in {name} JSON: {}", py_list_repr(&extras)));
    }
    Ok(())
}

fn require_nonempty(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be a non-empty string"));
    }
    Ok(())
}

/// Optional forward-compatible CWE-476/CWE-416 lifecycle annotation.
#[derive(Clone, Debug, PartialEq)]
pub struct LifecyclePrecondition {
    pub field: String,
    pub write_site_guard: String,
    pub read_site_lacks_guard: bool,
    pub notes: Option<String>,
}

impl LifecyclePrecondition {
    pub fn new(field: &str, write_site_guard: &str, read_site_lacks_guard: bool, notes: Option<&str>) -> Result<Self, String> {
        require_nonempty("LifecyclePrecondition.field", field)?;
        require_nonempty("LifecyclePrecondition.write_site_guard", write_site_guard)?;
        Ok(Self {
            field: field.to_string(),
            write_site_guard: write_site_guard.to_string(),
            read_site_lacks_guard,
            notes: notes.map(str::to_string),
        })
    }

    pub fn to_dict(&self) -> Value {
        let mut m = Map::new();
        m.insert("field".into(), Value::String(self.field.clone()));
        m.insert("write_site_guard".into(), Value::String(self.write_site_guard.clone()));
        m.insert("read_site_lacks_guard".into(), Value::Bool(self.read_site_lacks_guard));
        if let Some(n) = &self.notes {
            m.insert("notes".into(), Value::String(n.clone()));
        }
        Value::Object(m)
    }

    pub fn from_dict(data: &Value) -> Result<Self, String> {
        let obj = data.as_object().ok_or("LifecyclePrecondition data must be an object")?;
        check_extra_fields("LifecyclePrecondition", obj, LIFECYCLE_PRECONDITION_KEYS)?;
        let field = req_str(obj, "field")?;
        let write_site_guard = req_str(obj, "write_site_guard")?;
        let read_site_lacks_guard = obj
            .get("read_site_lacks_guard")
            .and_then(Value::as_bool)
            .ok_or("LifecyclePrecondition.read_site_lacks_guard must be bool")?;
        let notes = obj.get("notes").and_then(Value::as_str).map(str::to_string);
        Self::new(&field, &write_site_guard, read_site_lacks_guard, notes.as_deref())
    }
}

fn req_str(obj: &Map<String, Value>, key: &str) -> Result<String, String> {
    obj.get(key).and_then(Value::as_str).map(str::to_string).ok_or_else(|| format!("'{key}'"))
}

/// One labeled corpus entry (`GroundTruth`).
#[derive(Clone, Debug, PartialEq)]
pub struct GroundTruth {
    pub finding_id: String,
    pub verdict: String,
    pub rationale: String,
    pub labeler: String,
    pub labeled_at: String,
    pub fp_category: Option<String>,
    pub lifecycle_precondition: Option<LifecyclePrecondition>,
}

impl GroundTruth {
    pub fn new(
        finding_id: &str,
        verdict: &str,
        rationale: &str,
        labeler: &str,
        labeled_at: &str,
        fp_category: Option<&str>,
        lifecycle_precondition: Option<LifecyclePrecondition>,
    ) -> Result<Self, String> {
        require_nonempty("GroundTruth.finding_id", finding_id)?;
        require_nonempty("GroundTruth.rationale", rationale)?;
        require_nonempty("GroundTruth.labeler", labeler)?;
        if !iso_date_re().is_match(labeled_at) {
            return Err(format!("GroundTruth.labeled_at must be ISO YYYY-MM-DD, got {}", py_repr(labeled_at)));
        }
        if !VALID_VERDICTS_SORTED.contains(&verdict) {
            return Err(format!("verdict {} not in {}", py_repr(verdict), py_list_repr(VALID_VERDICTS_SORTED)));
        }
        if verdict == VERDICT_TRUE_POSITIVE && fp_category.is_some() {
            return Err("fp_category must be None for true_positive verdicts".to_string());
        }
        if verdict == VERDICT_FALSE_POSITIVE {
            match fp_category {
                None => return Err("fp_category required for false_positive verdicts".to_string()),
                Some(cat) if !VALID_FP_CATEGORIES_SORTED.contains(&cat) => {
                    return Err(format!("fp_category {} not in {}", py_repr(cat), py_list_repr(VALID_FP_CATEGORIES_SORTED)));
                }
                _ => {}
            }
        }
        Ok(Self {
            finding_id: finding_id.to_string(),
            verdict: verdict.to_string(),
            rationale: rationale.to_string(),
            labeler: labeler.to_string(),
            labeled_at: labeled_at.to_string(),
            fp_category: fp_category.map(str::to_string),
            lifecycle_precondition,
        })
    }

    pub fn to_dict(&self) -> Value {
        let mut m = Map::new();
        m.insert("schema_version".into(), Value::from(SCHEMA_VERSION));
        m.insert("finding_id".into(), Value::String(self.finding_id.clone()));
        m.insert("verdict".into(), Value::String(self.verdict.clone()));
        m.insert("fp_category".into(), self.fp_category.clone().map(Value::String).unwrap_or(Value::Null));
        m.insert("rationale".into(), Value::String(self.rationale.clone()));
        m.insert("labeler".into(), Value::String(self.labeler.clone()));
        m.insert("labeled_at".into(), Value::String(self.labeled_at.clone()));
        if let Some(lcp) = &self.lifecycle_precondition {
            m.insert("lifecycle_precondition".into(), lcp.to_dict());
        }
        Value::Object(m)
    }

    pub fn from_dict(data: &Value) -> Result<Self, String> {
        let obj = data.as_object().ok_or("GroundTruth data must be an object")?;
        check_extra_fields("GroundTruth", obj, GROUND_TRUTH_KEYS)?;
        let version = obj.get("schema_version").ok_or("'schema_version'")?;
        if version.as_i64() != Some(SCHEMA_VERSION) {
            return Err(format!(
                "GroundTruth schema_version {} != expected {SCHEMA_VERSION}; corpus upgrade required",
                py_num_repr(version)
            ));
        }
        let finding_id = req_str(obj, "finding_id")?;
        let verdict = req_str(obj, "verdict")?;
        let rationale = req_str(obj, "rationale")?;
        let labeler = req_str(obj, "labeler")?;
        let labeled_at = req_str(obj, "labeled_at")?;
        let fp_category = obj.get("fp_category").and_then(Value::as_str).map(str::to_string);
        let lcp = match obj.get("lifecycle_precondition") {
            Some(v) if !v.is_null() => Some(LifecyclePrecondition::from_dict(v)?),
            _ => None,
        };
        Self::new(&finding_id, &verdict, &rationale, &labeler, &labeled_at, fp_category.as_deref(), lcp)
    }

    pub fn to_json(&self, indent: Option<usize>) -> String {
        py_json::dumps(&self.to_dict(), indent)
    }

    pub fn from_json(text: &str) -> Result<Self, String> {
        let data: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        Self::from_dict(&data)
    }
}

/// `repr()` of a JSON number as Python would print it (`2`, not `2.0`).
fn py_num_repr(v: &Value) -> String {
    if let Some(i) = v.as_i64() {
        i.to_string()
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_fp() -> GroundTruth {
        GroundTruth::new("F1", "false_positive", "r", "me", "2026-01-02", Some("dead_code"), None).unwrap()
    }

    #[test]
    fn serialization() {
        let gt = ok_fp();
        assert_eq!(gt.to_json(None),
            r#"{"schema_version": 1, "finding_id": "F1", "verdict": "false_positive", "fp_category": "dead_code", "rationale": "r", "labeler": "me", "labeled_at": "2026-01-02"}"#);
        assert_eq!(gt.to_json(Some(2)),
            "{\n  \"schema_version\": 1,\n  \"finding_id\": \"F1\",\n  \"verdict\": \"false_positive\",\n  \"fp_category\": \"dead_code\",\n  \"rationale\": \"r\",\n  \"labeler\": \"me\",\n  \"labeled_at\": \"2026-01-02\"\n}");
        // Roundtrip.
        assert_eq!(GroundTruth::from_json(&gt.to_json(None)).unwrap(), gt);
    }

    #[test]
    fn lifecycle_precondition_serialization() {
        let lcp = LifecyclePrecondition::new("len", "if x", true, Some("n")).unwrap();
        let gt = GroundTruth::new("F2", "true_positive", "r", "me", "2026-01-02", None, Some(lcp)).unwrap();
        assert_eq!(gt.to_json(Some(2)),
            "{\n  \"schema_version\": 1,\n  \"finding_id\": \"F2\",\n  \"verdict\": \"true_positive\",\n  \"fp_category\": null,\n  \"rationale\": \"r\",\n  \"labeler\": \"me\",\n  \"labeled_at\": \"2026-01-02\",\n  \"lifecycle_precondition\": {\n    \"field\": \"len\",\n    \"write_site_guard\": \"if x\",\n    \"read_site_lacks_guard\": true,\n    \"notes\": \"n\"\n  }\n}");
    }

    fn err(r: Result<GroundTruth, String>) -> String {
        r.unwrap_err()
    }

    #[test]
    fn validation_errors() {
        assert_eq!(err(GroundTruth::new("", "true_positive", "r", "me", "2026-01-02", None, None)),
            "GroundTruth.finding_id must be a non-empty string");
        assert_eq!(err(GroundTruth::new("F", "true_positive", "r", "me", "01-02-2026", None, None)),
            "GroundTruth.labeled_at must be ISO YYYY-MM-DD, got '01-02-2026'");
        assert_eq!(err(GroundTruth::new("F", "maybe", "r", "me", "2026-01-02", None, None)),
            "verdict 'maybe' not in ['false_positive', 'true_positive']");
        assert_eq!(err(GroundTruth::new("F", "true_positive", "r", "me", "2026-01-02", Some("dead_code"), None)),
            "fp_category must be None for true_positive verdicts");
        assert_eq!(err(GroundTruth::new("F", "false_positive", "r", "me", "2026-01-02", None, None)),
            "fp_category required for false_positive verdicts");
        assert_eq!(err(GroundTruth::new("F", "false_positive", "r", "me", "2026-01-02", Some("nope"), None)),
            "fp_category 'nope' not in ['dead_code', 'framework_mitigation', 'infeasible_branch', 'missing_sanitizer_model', 'reflection_imprecision', 'type_constraint']");
    }

    #[test]
    fn from_dict_errors() {
        let extra: Value = serde_json::from_str(r#"{"schema_version":1,"finding_id":"F","verdict":"true_positive","rationale":"r","labeler":"me","labeled_at":"2026-01-02","bogus":1}"#).unwrap();
        assert_eq!(GroundTruth::from_dict(&extra).unwrap_err(), "unknown fields in GroundTruth JSON: ['bogus']");
        let bad_schema: Value = serde_json::from_str(r#"{"schema_version":2,"finding_id":"F","verdict":"true_positive","rationale":"r","labeler":"me","labeled_at":"2026-01-02"}"#).unwrap();
        assert_eq!(GroundTruth::from_dict(&bad_schema).unwrap_err(), "GroundTruth schema_version 2 != expected 1; corpus upgrade required");
    }
}
