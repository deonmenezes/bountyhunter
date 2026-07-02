//! CI-gate threshold evaluation — Rust port of the pure core of
//! `packages/sca/thresholds.py`. The argparse wiring (`add_threshold_args`,
//! `cfg_from_args`) and `print_result` stdout formatting stay Python.

use serde_json::Value;

use crate::findings::severity_rank;

/// Threshold knobs for "fail this build if …" logic (`ThresholdConfig`). All
/// fields default to a non-failing value.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ThresholdConfig {
    pub fail_on_severity: Option<String>,
    pub fail_on_kev: bool,
    pub fail_on_supply_chain: Option<String>,
    pub fail_on_hygiene: Option<String>,
    pub include_suppressed: bool,
    pub fail_on_capability_drift: bool,
    pub max_added_capability_buckets: Option<i64>,
}

impl ThresholdConfig {
    /// True when any gate is set (`is_active`); otherwise `evaluate` is a no-op.
    pub fn is_active(&self) -> bool {
        self.fail_on_severity.is_some()
            || self.fail_on_kev
            || self.fail_on_supply_chain.is_some()
            || self.fail_on_hygiene.is_some()
            || self.fail_on_capability_drift
            || self.max_added_capability_buckets.is_some()
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

/// `x` if it's a truthy string, else `None` — the `a or b or c` desc chain.
fn truthy_str(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// Evaluate findings `rows` against the thresholds (`evaluate`). Returns
/// `(passed, failure_messages)`.
pub fn evaluate(rows: &[Value], cfg: &ThresholdConfig) -> (bool, Vec<String>) {
    if !cfg.is_active() {
        return (true, Vec::new());
    }
    // `severity_rank(x) if x else None` — only when the string is non-empty.
    let floor = |o: &Option<String>| o.as_deref().filter(|s| !s.is_empty()).map(severity_rank);
    let sev_floor = floor(&cfg.fail_on_severity);
    let sc_floor = floor(&cfg.fail_on_supply_chain);
    let hyg_floor = floor(&cfg.fail_on_hygiene);

    let mut fails = Vec::new();
    for row in rows {
        let Some(obj) = row.as_object() else { continue };
        if obj.get("suppressed").map(json_truthy).unwrap_or(false) && !cfg.include_suppressed {
            continue;
        }
        let vuln_type = obj.get("vuln_type").and_then(Value::as_str).unwrap_or("");
        let sev = obj.get("severity").and_then(Value::as_str).unwrap_or("info");
        let rank = severity_rank(sev);
        let desc = truthy_str(obj.get("description"))
            .or_else(|| truthy_str(obj.get("id")))
            .unwrap_or("(no description)");

        if vuln_type == "sca:vulnerable_dependency" {
            if sev_floor.map_or(false, |f| rank >= f) {
                fails.push(format!("[{sev}] {desc}"));
                continue;
            }
            if cfg.fail_on_kev
                && obj.get("sca").and_then(|s| s.get("in_kev")).map(json_truthy).unwrap_or(false)
            {
                fails.push(format!("[KEV] {desc}"));
            }
        } else if vuln_type.starts_with("sca:supply_chain:") {
            if sc_floor.map_or(false, |f| rank >= f) {
                fails.push(format!("[supply-chain {sev}] {desc}"));
            }
            if vuln_type == "sca:supply_chain:image_capability_drift" {
                if cfg.fail_on_capability_drift {
                    fails.push(format!("[capability-drift] {desc}"));
                }
                if let Some(max) = cfg.max_added_capability_buckets {
                    let added_len = obj
                        .get("evidence")
                        .and_then(Value::as_object)
                        .and_then(|ev| ev.get("added_buckets"))
                        .and_then(Value::as_array)
                        .map(|a| a.len() as i64)
                        .unwrap_or(0);
                    if added_len > max {
                        fails.push(format!("[capability-drift +{added_len} buckets > max {max}] {desc}"));
                    }
                }
            }
        } else if vuln_type.starts_with("sca:hygiene:") {
            if hyg_floor.map_or(false, |f| rank >= f) {
                fails.push(format!("[hygiene {sev}] {desc}"));
            }
        }
    }

    (fails.is_empty(), fails)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(rows: &[Value], cfg: ThresholdConfig) -> (bool, Vec<String>) {
        evaluate(rows, &cfg)
    }

    #[test]
    fn inactive_passes() {
        let (p, f) = ev(&[json!({"vuln_type": "sca:vulnerable_dependency", "severity": "high", "id": "X"})], ThresholdConfig::default());
        assert!(p && f.is_empty());
    }

    #[test]
    fn severity_gate_and_kev_continue() {
        let rows = [
            json!({"vuln_type": "sca:vulnerable_dependency", "severity": "high", "description": "CVE-1"}),
            json!({"vuln_type": "sca:vulnerable_dependency", "severity": "low", "description": "CVE-2"}),
        ];
        let (p, f) = ev(&rows, ThresholdConfig { fail_on_severity: Some("medium".into()), ..Default::default() });
        assert_eq!((p, f), (false, vec!["[high] CVE-1".to_string()]));

        // sev gate fires then `continue` -> KEV not also reported.
        let rows = [json!({"vuln_type": "sca:vulnerable_dependency", "severity": "high", "id": "HK", "sca": {"in_kev": true}})];
        let (_, f) = ev(&rows, ThresholdConfig { fail_on_severity: Some("low".into()), fail_on_kev: true, ..Default::default() });
        assert_eq!(f, vec!["[high] HK".to_string()]);

        // KEV alone.
        let rows = [json!({"vuln_type": "sca:vulnerable_dependency", "severity": "low", "id": "K", "sca": {"in_kev": true}})];
        let (_, f) = ev(&rows, ThresholdConfig { fail_on_kev: true, ..Default::default() });
        assert_eq!(f, vec!["[KEV] K".to_string()]);
    }

    #[test]
    fn supply_chain_hygiene_suppressed() {
        let rows = [json!({"vuln_type": "sca:supply_chain:typosquat_candidate", "severity": "medium", "id": "S"})];
        assert_eq!(ev(&rows, ThresholdConfig { fail_on_supply_chain: Some("low".into()), ..Default::default() }).1, vec!["[supply-chain medium] S"]);

        let rows = [json!({"vuln_type": "sca:hygiene:yanked_version", "severity": "medium", "id": "H"})];
        assert_eq!(ev(&rows, ThresholdConfig { fail_on_hygiene: Some("medium".into()), ..Default::default() }).1, vec!["[hygiene medium] H"]);

        // Suppressed row skipped unless include_suppressed.
        let rows = [json!({"vuln_type": "sca:vulnerable_dependency", "severity": "critical", "id": "SUP", "suppressed": true})];
        assert!(ev(&rows, ThresholdConfig { fail_on_severity: Some("low".into()), ..Default::default() }).0);
    }

    #[test]
    fn capability_drift_and_desc_fallback() {
        let rows = [json!({"vuln_type": "sca:supply_chain:image_capability_drift", "severity": "info", "id": "D", "evidence": {"added_buckets": ["a", "b", "c"]}})];
        let (_, f) = ev(&rows, ThresholdConfig { fail_on_capability_drift: true, max_added_capability_buckets: Some(2), ..Default::default() });
        assert_eq!(f, vec!["[capability-drift] D".to_string(), "[capability-drift +3 buckets > max 2] D".to_string()]);

        // No description/id -> "(no description)".
        let rows = [json!({"vuln_type": "sca:hygiene:x", "severity": "high"})];
        assert_eq!(ev(&rows, ThresholdConfig { fail_on_hygiene: Some("low".into()), ..Default::default() }).1, vec!["[hygiene high] (no description)"]);
    }
}
