//! Render a finding's verified exemplars as a prompt block — Rust port of the
//! pure core of `core/verified_outcome/exemplars.py`. `exemplar_block_for_finding`
//! (best-effort collect + active-project resolution) stays Python.

use mantishack_core_security::log_sanitisation::escape_nonprintable;
use mantishack_core_security::prompt_envelope::neutralize_tag_forgery;
use serde_json::Value;

use crate::collect::{rank_outcomes_for_finding, ScoredOutcome};
use crate::types::{OutcomeStatus, VerifiedOutcome};

const HEADER: &str = "## MANTISHACK-verified exemplars";
const INTRO: &str = "Findings like this one that MANTISHACK has *previously confirmed* by execution / adjudication. Use them to calibrate how this bug-class manifests and is confirmed here \u{2014} not as patterns to match.";

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

/// Defang an untrusted field for a prompt (`_safe`, cap 120): forge-neutralise,
/// escape control chars, length-cap with an ellipsis.
fn safe(text: &str) -> String {
    let escaped = escape_nonprintable(&neutralize_tag_forgery(text), false);
    let chars: Vec<char> = escaped.chars().collect();
    if chars.len() <= 120 {
        escaped
    } else {
        format!("{}…", chars[..120].iter().collect::<String>())
    }
}

fn safe_val(v: &Value) -> String {
    safe(&py_str(v))
}

fn render_one(scored: &ScoredOutcome) -> String {
    let o = &scored.outcome;
    let label = if !o.finding_id.is_empty() { safe(&o.finding_id) } else { "(unlinked)".to_string() };
    let where_parts: Vec<String> = [&o.cwe_id, &o.file]
        .into_iter()
        .filter_map(|p| p.as_deref().filter(|s| !s.is_empty()).map(safe))
        .collect();
    let where_ = if where_parts.is_empty() { "unknown location".to_string() } else { where_parts.join(" in ") };

    let mut evidence_bits: Vec<String> = Vec::new();
    if let Some(obs) = o.evidence.get("observed_outcome") {
        if json_truthy(obs) {
            evidence_bits.push(safe_val(obs));
        }
    }
    for k in ["signal", "sanitizer"] {
        if let Some(v) = o.evidence.get(k) {
            if json_truthy(v) {
                evidence_bits.push(format!("{k}={}", safe_val(v)));
            }
        }
    }
    let evidence = if evidence_bits.is_empty() { "no detail".to_string() } else { evidence_bits.join(", ") };
    let repro = if o.reproducible { "reproducible" } else { "point-in-time (not replayable)" };
    format!(
        "**{label} \u{2014} {where_}** (match: {})\nConfirmed by `{}` \u{2192} {}; evidence: {evidence}; {repro}.",
        scored.reason,
        o.oracle.value(),
        o.status.value(),
    )
}

/// Render the finding's nearest verified outcomes as a prompt block
/// (`render_verified_exemplars`). `""` when nothing matches. Trailing entries
/// are dropped until within `max_bytes`; at least one is always kept.
pub fn render_verified_exemplars(
    finding: &Value,
    outcomes: &[VerifiedOutcome],
    top_k: usize,
    statuses: &[OutcomeStatus],
    max_bytes: usize,
) -> String {
    let ranked = rank_outcomes_for_finding(outcomes, finding, top_k, statuses);
    if ranked.is_empty() {
        return String::new();
    }

    let header = format!("{HEADER}\n\n{INTRO}");
    let mut entries: Vec<String> = ranked.iter().map(render_one).collect();

    loop {
        let mut parts = vec![header.clone()];
        parts.extend(entries.iter().cloned());
        let block = format!("{}\n", parts.join("\n\n").trim_end());
        if block.len() <= max_bytes || entries.len() == 1 {
            return block;
        }
        entries.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Oracle;
    use serde_json::json;

    fn vo(fid: &str, cwe: &str, file: &str, ev: Value) -> VerifiedOutcome {
        VerifiedOutcome {
            finding_id: fid.into(), oracle: Oracle::Sandbox, status: OutcomeStatus::Verified,
            reproducible: true, evidence: ev, cwe_id: Some(cwe.into()), file: Some(file.into()),
            produced_by: None, authorization: None, timestamp: String::new(),
        }
    }

    #[test]
    fn renders_block() {
        let finding = json!({"id": "F1", "cwe": "CWE-89", "file": "a.py"});
        let outs = [vo("F1", "CWE-89", "a.py", json!({"observed_outcome": "crash", "signal": "segv"}))];
        let expected = "\
## MANTISHACK-verified exemplars

Findings like this one that MANTISHACK has *previously confirmed* by execution / adjudication. Use them to calibrate how this bug-class manifests and is confirmed here \u{2014} not as patterns to match.

**F1 \u{2014} CWE-89 in a.py** (match: exact finding-id match)
Confirmed by `sandbox` \u{2192} verified; evidence: crash, signal=segv; reproducible.
";
        assert_eq!(render_verified_exemplars(&finding, &outs, 3, &[OutcomeStatus::Verified], 4096), expected);
    }

    #[test]
    fn empty_when_no_match() {
        assert_eq!(render_verified_exemplars(&json!({"id": "NONE"}), &[], 3, &[OutcomeStatus::Verified], 4096), "");
    }
}
