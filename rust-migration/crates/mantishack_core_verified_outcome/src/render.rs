//! Human-readable summary of verified outcomes — Rust port of
//! `core/verified_outcome/render.py`. Pure; reuses the ported
//! `escape_nonprintable` for terminal defanging.

use mantishack_core_security::log_sanitisation::escape_nonprintable;
use serde_json::Value;

use crate::types::{Oracle, OutcomeStatus, VerifiedOutcome};

const ORACLES: [Oracle; 5] = [Oracle::Sandbox, Oracle::Fuzzer, Oracle::Codeql, Oracle::Web, Oracle::Manual];
const STATUSES: [OutcomeStatus; 3] = [OutcomeStatus::Verified, OutcomeStatus::Refuted, OutcomeStatus::Inconclusive];

fn status_label(st: OutcomeStatus) -> &'static str {
    match st {
        OutcomeStatus::Verified => "Verified",
        OutcomeStatus::Refuted => "Refuted",
        OutcomeStatus::Inconclusive => "Inconclusive",
    }
}

/// Defang an untrusted field for terminal output (`_safe`): escape control
/// chars/newlines, then length-cap with an ellipsis.
fn safe(text: &str, cap: usize) -> String {
    let escaped = escape_nonprintable(text, false);
    let chars: Vec<char> = escaped.chars().collect();
    if chars.len() <= cap {
        escaped
    } else {
        format!("{}…", chars[..cap].iter().collect::<String>())
    }
}

fn py_str(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
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

/// Render a grouped summary: total, an oracle × status table, and the confirmed
/// findings (`render_outcome_summary`). Trailing-newline terminated.
pub fn render_outcome_summary(outcomes: &[VerifiedOutcome]) -> String {
    if outcomes.is_empty() {
        return "No verified outcomes found.\n".to_string();
    }

    let mut lines: Vec<String> = vec![format!("Verified outcomes: {} total", outcomes.len()), String::new()];

    let count = |oracle: Oracle, st: OutcomeStatus| outcomes.iter().filter(|o| o.oracle == oracle && o.status == st).count();

    lines.push("By oracle x status:".to_string());
    for oracle in ORACLES {
        let cells: Vec<(OutcomeStatus, usize)> =
            STATUSES.iter().filter_map(|&st| { let n = count(oracle, st); (n > 0).then_some((st, n)) }).collect();
        if cells.is_empty() {
            continue;
        }
        let cell_str = cells.iter().map(|(st, n)| format!("{}={n}", status_label(*st))).collect::<Vec<_>>().join("  ");
        lines.push(format!("  {:<8} {cell_str}", oracle.value()));
    }

    let verified: Vec<&VerifiedOutcome> = outcomes.iter().filter(|o| o.status == OutcomeStatus::Verified).collect();
    if !verified.is_empty() {
        lines.push(String::new());
        lines.push(format!("Confirmed ({}):", verified.len()));
        for o in verified {
            let fid = if !o.finding_id.is_empty() { safe(&o.finding_id, 200) } else { "(unlinked)".to_string() };
            let cwe = o.cwe_id.as_deref().filter(|s| !s.is_empty()).map(|s| safe(s, 200)).unwrap_or_else(|| "?".to_string());
            let where_ = o.file.as_deref().filter(|s| !s.is_empty()).map(|s| safe(s, 200)).unwrap_or_else(|| "?".to_string());
            let obs = o.evidence.get("observed_outcome");
            let repro = if o.reproducible { "reproducible" } else { "point-in-time" };
            let detail = match obs {
                Some(v) if json_truthy(v) => format!("{}: {}; {repro}", o.oracle.value(), safe(&py_str(v), 200)),
                _ => format!("{}; {repro}", o.oracle.value()),
            };
            lines.push(format!("  - {fid}  {cwe}  {where_}  [{detail}]"));
        }
    }

    format!("{}\n", lines.join("\n").trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vo(fid: &str, oracle: Oracle, status: OutcomeStatus, repro: bool, cwe: Option<&str>, file: Option<&str>, ev: Value) -> VerifiedOutcome {
        VerifiedOutcome {
            finding_id: fid.into(), oracle, status, reproducible: repro, evidence: ev,
            cwe_id: cwe.map(str::to_string), file: file.map(str::to_string),
            produced_by: None, authorization: None, timestamp: String::new(),
        }
    }

    #[test]
    fn empty_corpus() {
        assert_eq!(render_outcome_summary(&[]), "No verified outcomes found.\n");
    }

    #[test]
    fn grouped_summary() {
        let items = vec![
            vo("F1", Oracle::Sandbox, OutcomeStatus::Verified, true, Some("CWE-89"), Some("a.py"), json!({"observed_outcome": "crash"})),
            vo("F2", Oracle::Sandbox, OutcomeStatus::Refuted, true, None, None, json!({})),
            vo("", Oracle::Web, OutcomeStatus::Verified, false, None, None, json!({})),
        ];
        let expected = "\
Verified outcomes: 3 total

By oracle x status:
  sandbox  Verified=1  Refuted=1
  web      Verified=1

Confirmed (2):
  - F1  CWE-89  a.py  [sandbox: crash; reproducible]
  - (unlinked)  ?  ?  [web; point-in-time]
";
        assert_eq!(render_outcome_summary(&items), expected);
    }
}
