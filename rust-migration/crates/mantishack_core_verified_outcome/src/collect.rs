//! Rank `VerifiedOutcome` records against a finding — Rust port of the pure
//! scoring/ranking core of `core/verified_outcome/collect.py`. `collect_outcomes`
//! (witness-store discovery) stays Python. Recency ordering compares the ISO
//! timestamp strings descending — faithful for the canonical UTC timestamps
//! `to_dict` emits (full epoch ordering across offsets would need a chrono port).

use serde_json::Value;

use crate::types::{OutcomeStatus, VerifiedOutcome};

/// A verified outcome scored against a particular finding (`ScoredOutcome`).
#[derive(Clone, Debug, PartialEq)]
pub struct ScoredOutcome {
    pub outcome: VerifiedOutcome,
    pub score: i64,
    pub reason: &'static str,
}

fn truthy_str<'a>(finding: &'a Value, key: &str) -> Option<&'a str> {
    finding.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// Score one outcome against a finding (`_score_outcome`).
pub fn score_outcome(outcome: &VerifiedOutcome, finding: &Value) -> (i64, &'static str) {
    let fid = truthy_str(finding, "id");
    let fcwe = truthy_str(finding, "cwe_id").or_else(|| truthy_str(finding, "cwe"));
    let ffile = truthy_str(finding, "file").or_else(|| truthy_str(finding, "file_path"));

    if let Some(f) = fid {
        if !outcome.finding_id.is_empty() && outcome.finding_id == f {
            return (10, "exact finding-id match");
        }
    }
    if fcwe.is_some() && outcome.cwe_id.as_deref() == fcwe && ffile.is_some() && outcome.file.as_deref() == ffile {
        return (7, "cwe + file match");
    }
    if ffile.is_some() && outcome.file.as_deref() == ffile {
        return (4, "file match");
    }
    if fcwe.is_some() && outcome.cwe_id.as_deref() == fcwe {
        return (2, "cwe match");
    }
    (0, "no structured signal")
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

fn witness_hash(o: &VerifiedOutcome) -> String {
    match o.evidence.get("witness_bytes_hash") {
        Some(v) => py_str(v),
        None => String::new(),
    }
}

/// Return the `top_k` outcomes most relevant to `finding`
/// (`rank_outcomes_for_finding`). Filters to `statuses` (empty = no filter),
/// drops score-0, and tie-breaks reproducible-first, then recency, then a
/// deterministic evidence-hash key.
pub fn rank_outcomes_for_finding(
    outcomes: &[VerifiedOutcome],
    finding: &Value,
    top_k: usize,
    statuses: &[OutcomeStatus],
) -> Vec<ScoredOutcome> {
    let mut scored: Vec<ScoredOutcome> = Vec::new();
    for o in outcomes {
        if !statuses.is_empty() && !statuses.contains(&o.status) {
            continue;
        }
        let (score, reason) = score_outcome(o, finding);
        if score == 0 {
            continue;
        }
        scored.push(ScoredOutcome { outcome: o.clone(), score, reason });
    }

    scored.sort_by(|a, b| {
        let repro = |s: &ScoredOutcome| if s.outcome.reproducible { 0 } else { 1 };
        b.score
            .cmp(&a.score) // -score
            .then(repro(a).cmp(&repro(b)))
            .then(b.outcome.timestamp.cmp(&a.outcome.timestamp)) // -timestamp (recency)
            .then(witness_hash(&a.outcome).cmp(&witness_hash(&b.outcome)))
    });
    scored.truncate(top_k);
    scored
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn outcome(fid: &str, cwe: &str, file: &str, status: OutcomeStatus, repro: bool, ts: &str, wbh: &str) -> VerifiedOutcome {
        VerifiedOutcome {
            finding_id: fid.into(),
            oracle: crate::types::Oracle::Sandbox,
            status,
            reproducible: repro,
            evidence: if wbh.is_empty() { json!({}) } else { json!({"witness_bytes_hash": wbh}) },
            cwe_id: Some(cwe.into()),
            file: Some(file.into()),
            produced_by: None,
            authorization: None,
            timestamp: ts.into(),
        }
    }
    fn v(fid: &str, cwe: &str, file: &str) -> VerifiedOutcome {
        outcome(fid, cwe, file, OutcomeStatus::Verified, true, "", "")
    }

    #[test]
    fn scoring_tiers() {
        let f = json!({"id": "F1", "cwe": "CWE-89", "file": "a.py"});
        assert_eq!(score_outcome(&v("F1", "CWE-89", "a.py"), &f), (10, "exact finding-id match"));
        assert_eq!(score_outcome(&v("X", "CWE-89", "a.py"), &f), (7, "cwe + file match"));
        assert_eq!(score_outcome(&v("X", "CWE-1", "a.py"), &json!({"cwe": "CWE-89", "file": "a.py"})), (4, "file match"));
        assert_eq!(score_outcome(&v("X", "CWE-89", "z.py"), &json!({"cwe": "CWE-89", "file": "a.py"})), (2, "cwe match"));
        assert_eq!(score_outcome(&v("X", "CWE-1", "z.py"), &f), (0, "no structured signal"));
    }

    #[test]
    fn ranking_recency_and_filter() {
        let f = json!({"id": "FID", "cwe": "CWE-89", "file": "a.py"});
        let outcomes = vec![
            outcome("FID", "CWE-89", "a.py", OutcomeStatus::Verified, true, "2026-01-02T00:00:00+00:00", ""), // 10
            outcome("X", "CWE-89", "a.py", OutcomeStatus::Verified, true, "2026-03-01T00:00:00+00:00", ""),   // 7 newer
            outcome("Y", "CWE-89", "a.py", OutcomeStatus::Verified, true, "2026-01-01T00:00:00+00:00", ""),   // 7 older
            outcome("Z", "CWE-1", "a.py", OutcomeStatus::Verified, true, "2026-01-01T00:00:00+00:00", ""),    // 4
            outcome("R", "CWE-1", "z.py", OutcomeStatus::Refuted, true, "", ""),                              // filtered
        ];
        let ranked = rank_outcomes_for_finding(&outcomes, &f, 3, &[OutcomeStatus::Verified]);
        let ids: Vec<&str> = ranked.iter().map(|s| s.outcome.finding_id.as_str()).collect();
        assert_eq!(ids, vec!["FID", "X", "Y"]); // score desc, then recency
    }

    #[test]
    fn ranking_reproducible_first() {
        let f = json!({"id": "FID", "cwe": "CWE-89", "file": "a.py"});
        let outcomes = vec![
            outcome("A", "CWE-89", "a.py", OutcomeStatus::Verified, false, "2026-01-02T00:00:00+00:00", ""),
            outcome("B", "CWE-89", "a.py", OutcomeStatus::Verified, true, "2026-01-02T00:00:00+00:00", ""),
        ];
        let ranked = rank_outcomes_for_finding(&outcomes, &f, 5, &[OutcomeStatus::Verified]);
        let ids: Vec<&str> = ranked.iter().map(|s| s.outcome.finding_id.as_str()).collect();
        assert_eq!(ids, vec!["B", "A"]); // reproducible-first
    }
}
