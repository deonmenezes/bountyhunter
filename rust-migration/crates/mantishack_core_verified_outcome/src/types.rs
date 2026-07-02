//! The verified-outcome data model (`Oracle`, `OutcomeStatus`, `VerifiedOutcome`).

use serde_json::{json, Map, Value};

/// Which mechanism adjudicated the outcome (`Oracle`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Oracle {
    Sandbox,
    Fuzzer,
    Codeql,
    Web,
    Manual,
}

impl Oracle {
    pub fn value(self) -> &'static str {
        match self {
            Oracle::Sandbox => "sandbox",
            Oracle::Fuzzer => "fuzzer",
            Oracle::Codeql => "codeql",
            Oracle::Web => "web",
            Oracle::Manual => "manual",
        }
    }

    /// `Oracle(value)`; `Err` mirrors Python's enum ValueError message.
    pub fn from_value(s: &str) -> Result<Self, String> {
        match s {
            "sandbox" => Ok(Oracle::Sandbox),
            "fuzzer" => Ok(Oracle::Fuzzer),
            "codeql" => Ok(Oracle::Codeql),
            "web" => Ok(Oracle::Web),
            "manual" => Ok(Oracle::Manual),
            other => Err(format!("'{other}' is not a valid Oracle")),
        }
    }
}

/// What the oracle established about the finding (`OutcomeStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeStatus {
    Verified,
    Refuted,
    Inconclusive,
}

impl OutcomeStatus {
    pub fn value(self) -> &'static str {
        match self {
            OutcomeStatus::Verified => "verified",
            OutcomeStatus::Refuted => "refuted",
            OutcomeStatus::Inconclusive => "inconclusive",
        }
    }

    pub fn from_value(s: &str) -> Result<Self, String> {
        match s {
            "verified" => Ok(OutcomeStatus::Verified),
            "refuted" => Ok(OutcomeStatus::Refuted),
            "inconclusive" => Ok(OutcomeStatus::Inconclusive),
            other => Err(format!("'{other}' is not a valid OutcomeStatus")),
        }
    }
}

fn json_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `datetime.fromisoformat(s)` then `.isoformat()` for the common cases: a
/// trailing `Z` becomes `+00:00`; already-canonical strings pass through.
fn normalize_timestamp(s: &str) -> String {
    if let Some(stripped) = s.strip_suffix('Z') {
        format!("{stripped}+00:00")
    } else {
        s.to_string()
    }
}

/// One oracle's verdict on one finding (`VerifiedOutcome`).
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedOutcome {
    pub finding_id: String,
    pub oracle: Oracle,
    pub status: OutcomeStatus,
    pub reproducible: bool,
    pub evidence: Value,
    pub cwe_id: Option<String>,
    pub file: Option<String>,
    pub produced_by: Option<String>,
    pub authorization: Option<String>,
    pub timestamp: String,
}

fn opt_str(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_string)
}

impl VerifiedOutcome {
    pub fn to_dict(&self) -> Value {
        let mut m = Map::new();
        m.insert("finding_id".into(), Value::String(self.finding_id.clone()));
        m.insert("oracle".into(), Value::String(self.oracle.value().to_string()));
        m.insert("status".into(), Value::String(self.status.value().to_string()));
        m.insert("reproducible".into(), Value::Bool(self.reproducible));
        m.insert("evidence".into(), if self.evidence.is_object() { self.evidence.clone() } else { json!({}) });
        m.insert("cwe_id".into(), opt_to_value(&self.cwe_id));
        m.insert("file".into(), opt_to_value(&self.file));
        m.insert("produced_by".into(), opt_to_value(&self.produced_by));
        m.insert("authorization".into(), opt_to_value(&self.authorization));
        m.insert("timestamp".into(), Value::String(self.timestamp.clone()));
        Value::Object(m)
    }

    /// Inverse of `to_dict`, tolerant of extra keys (`from_dict`). A missing /
    /// non-string `timestamp` yields `""` (Python would substitute `now()`).
    pub fn from_dict(data: &Value) -> Result<Self, String> {
        let obj = data.as_object().ok_or("VerifiedOutcome data must be an object")?;
        let timestamp = match obj.get("timestamp") {
            Some(Value::String(s)) => normalize_timestamp(s),
            _ => String::new(),
        };
        let finding_id = obj.get("finding_id").and_then(Value::as_str).map(str::to_string).ok_or("'finding_id'")?;
        let oracle = Oracle::from_value(obj.get("oracle").and_then(Value::as_str).ok_or("'oracle'")?)?;
        let status = OutcomeStatus::from_value(obj.get("status").and_then(Value::as_str).ok_or("'status'")?)?;
        let reproducible = obj.get("reproducible").map(json_truthy).unwrap_or(false);
        let evidence = match obj.get("evidence") {
            Some(v) if v.is_object() && json_truthy(v) => v.clone(),
            _ => json!({}),
        };
        Ok(VerifiedOutcome {
            finding_id,
            oracle,
            status,
            reproducible,
            evidence,
            cwe_id: opt_str(obj.get("cwe_id")),
            file: opt_str(obj.get("file")),
            produced_by: opt_str(obj.get("produced_by")),
            authorization: opt_str(obj.get("authorization")),
            timestamp,
        })
    }
}

fn opt_to_value(o: &Option<String>) -> Value {
    o.clone().map(Value::String).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_values_and_errors() {
        assert_eq!(Oracle::Sandbox.value(), "sandbox");
        assert_eq!(Oracle::from_value("web"), Ok(Oracle::Web));
        assert_eq!(Oracle::from_value("bogus"), Err("'bogus' is not a valid Oracle".to_string()));
        assert_eq!(OutcomeStatus::from_value("nope"), Err("'nope' is not a valid OutcomeStatus".to_string()));
    }

    #[test]
    fn roundtrip_full() {
        let d = json!({
            "finding_id": "F1", "oracle": "sandbox", "status": "verified", "reproducible": true,
            "evidence": {"k": "v"}, "cwe_id": "CWE-89", "file": "a.py", "produced_by": "tool",
            "authorization": null, "timestamp": "2026-01-02T03:04:05+00:00"
        });
        let vo = VerifiedOutcome::from_dict(&d).unwrap();
        assert_eq!(vo.to_dict(), d);
    }

    #[test]
    fn minimal_defaults() {
        let vo = VerifiedOutcome::from_dict(&json!({
            "finding_id": "F", "oracle": "web", "status": "refuted", "timestamp": "2026-01-02T00:00:00+00:00"
        })).unwrap();
        assert_eq!(vo.to_dict(), json!({
            "finding_id": "F", "oracle": "web", "status": "refuted", "reproducible": false,
            "evidence": {}, "cwe_id": null, "file": null, "produced_by": null, "authorization": null,
            "timestamp": "2026-01-02T00:00:00+00:00"
        }));
    }

    #[test]
    fn from_dict_errors_and_z_normalisation() {
        assert_eq!(VerifiedOutcome::from_dict(&json!({"finding_id": "F", "oracle": "bogus", "status": "verified", "timestamp": "t"})).unwrap_err(),
            "'bogus' is not a valid Oracle");
        assert_eq!(VerifiedOutcome::from_dict(&json!({"finding_id": "F", "oracle": "web", "status": "nope", "timestamp": "t"})).unwrap_err(),
            "'nope' is not a valid OutcomeStatus");
        // Z suffix -> +00:00.
        let vo = VerifiedOutcome::from_dict(&json!({"finding_id": "F", "oracle": "web", "status": "verified", "timestamp": "2026-01-02T00:00:00Z"})).unwrap();
        assert_eq!(vo.timestamp, "2026-01-02T00:00:00+00:00");
    }
}
