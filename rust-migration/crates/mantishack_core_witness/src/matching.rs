//! Rank witnesses by how well they match a given finding.
//!
//! Faithful Rust port of core/witness/matching.py.
//!
//! Ranking (higher score → better match):
//!
//!   10  Exact finding-id match
//!        `outcome_detail["finding_id"] == finding["id"]`
//!
//!   7   CWE + file match
//!        `outcome_detail["cwe_id"] == finding["cwe_id"]` AND
//!        `outcome_detail["file_path"] == finding["file"]`
//!
//!   4   File match
//!        `outcome_detail["file_path"] == finding["file"]`
//!
//!   2   Same target binary
//!        witness has `target_binary_hash` AND finding has a binary path.
//!
//!   0   No structured signal — consumer should treat verdict cautiously.
//!
//! Ties broken by: source priority > outcome richness > bytes_hash lex order.

use std::path::PathBuf;

use crate::types::{Witness, WitnessOutcome, WitnessSource};
use serde_json::Value;

// ── WitnessMatch ──────────────────────────────────────────────────────────────

/// A scored witness candidate for a given finding.
///
/// Mirrors Python's `WitnessMatch` frozen dataclass.
#[derive(Debug, Clone)]
pub struct WitnessMatch {
    pub witness: Witness,
    /// Path to the `WitnessStore` root this witness came from.
    /// `None` when the witness was constructed without a backing store.
    pub store_root: Option<PathBuf>,
    pub score: i32,
    pub reason: String,
}

impl WitnessMatch {
    /// True iff the match score is above the "no structured signal" threshold.
    /// Consumers may want to skip score-0 matches entirely.
    pub fn is_real(&self) -> bool {
        self.score > 0
    }
}

// ── Priority helpers ──────────────────────────────────────────────────────────

fn source_priority(src: &WitnessSource) -> i32 {
    match src {
        WitnessSource::LlmEmitRun => 2,
        WitnessSource::Fuzz => 1,
        _ => 0,
    }
}

fn outcome_priority(outcome: &WitnessOutcome) -> i32 {
    match outcome {
        WitnessOutcome::FlagCaptured => 4, // rare but most-specific
        WitnessOutcome::SanitizerReport => 3,
        WitnessOutcome::ExitSignal => 2,
        _ => 1,
    }
}

// ── score_witness_for_finding ─────────────────────────────────────────────────

/// Return `(score, reason)` for one witness against one finding.
///
/// `finding` is a `serde_json::Value::Object` with keys like `id`, `cwe_id`,
/// `cwe`, `file`, `file_path`, `feasibility.binary_path`, mirroring the
/// Python `Dict[str, Any]` the rest of the pipeline produces.
///
/// Consumers loop this over a witness list and pick the maxima via
/// `best_match_for_finding`.
pub fn score_witness_for_finding(
    witness: &Witness,
    finding: &Value,
) -> (i32, &'static str) {
    let detail = &witness.outcome_detail;
    let empty = serde_json::Map::new();
    let finding_obj = finding.as_object().unwrap_or(&empty);

    let finding_id = finding_obj.get("id").and_then(|v| v.as_str());
    let finding_cwe = finding_obj
        .get("cwe_id")
        .or_else(|| finding_obj.get("cwe"))
        .and_then(|v| v.as_str());
    let finding_file = finding_obj
        .get("file")
        .or_else(|| finding_obj.get("file_path"))
        .and_then(|v| v.as_str());
    let binary_path = finding_obj
        .get("feasibility")
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("binary_path"))
        .and_then(|v| v.as_str());

    // Precedence 1: exact finding-id match
    if let Some(fid) = finding_id {
        if detail.get("finding_id").and_then(|v| v.as_str()) == Some(fid) {
            return (10, "exact finding-id match");
        }
    }

    // Precedence 2: CWE + file match
    if let (Some(fcwe), Some(ffile)) = (finding_cwe, finding_file) {
        let detail_cwe = detail.get("cwe_id").and_then(|v| v.as_str());
        let detail_file = detail.get("file_path").and_then(|v| v.as_str());
        if detail_cwe == Some(fcwe) && detail_file == Some(ffile) {
            return (7, "cwe + file match");
        }
    }

    // Precedence 3: file match
    if let Some(ffile) = finding_file {
        if detail.get("file_path").and_then(|v| v.as_str()) == Some(ffile) {
            return (4, "file match");
        }
    }

    // Precedence 4: binary-hash fallback for fuzz witnesses
    if witness.target_binary_hash.is_some() && binary_path.is_some() {
        return (2, "same target binary (hash-pending)");
    }

    (0, "no structured signal")
}

// ── best_match_for_finding ────────────────────────────────────────────────────

/// Pick the best-ranked witness for `finding` from an iterable of
/// `(store_root, Witness)` pairs.
///
/// Returns `None` when no candidate scores above 0 (i.e. no structured
/// signal — caller should treat as "no witness").
///
/// Tie-break order: score desc → source priority desc → outcome richness
/// desc → bytes_hash lex asc (deterministic).
pub fn best_match_for_finding(
    witnesses: impl IntoIterator<Item = (Option<PathBuf>, Witness)>,
    finding: &Value,
) -> Option<WitnessMatch> {
    let mut candidates: Vec<WitnessMatch> = witnesses
        .into_iter()
        .filter_map(|(store_root, w)| {
            let (score, reason) = score_witness_for_finding(&w, finding);
            if score == 0 {
                return None;
            }
            Some(WitnessMatch {
                witness: w,
                store_root,
                score,
                reason: reason.to_string(),
            })
        })
        .collect();

    if candidates.is_empty() {
        return None;
    }

    candidates.sort_by(|a, b| {
        // Higher score wins.
        b.score
            .cmp(&a.score)
            // Higher source priority wins.
            .then_with(|| {
                source_priority(&b.witness.source).cmp(&source_priority(&a.witness.source))
            })
            // Higher outcome richness wins.
            .then_with(|| {
                outcome_priority(&b.witness.observed_outcome)
                    .cmp(&outcome_priority(&a.witness.observed_outcome))
            })
            // Lex order on bytes_hash (deterministic tie-breaker, ascending).
            .then_with(|| a.witness.bytes_hash.cmp(&b.witness.bytes_hash))
    });

    candidates.into_iter().next()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Witness, WitnessOutcome, WitnessSource};
    use serde_json::json;

    const VALID_HASH: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALID_HASH_B: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn make_witness_with_detail(
        detail: serde_json::Map<String, Value>,
        src: WitnessSource,
        outcome: WitnessOutcome,
        tbh: Option<String>,
    ) -> Witness {
        let mut w = Witness::new(VALID_HASH.to_string(), src, outcome).unwrap();
        w.outcome_detail = detail.into_iter().collect();
        w.target_binary_hash = tbh;
        w
    }

    fn plain_fuzz_exit() -> Witness {
        make_witness_with_detail(
            serde_json::Map::new(),
            WitnessSource::Fuzz,
            WitnessOutcome::ExitSignal,
            None,
        )
    }

    // -- Golden: score_witness_for_finding --

    #[test]
    fn test_score_exact_finding_id() {
        // Python: score=10, reason="exact finding-id match"
        let detail = serde_json::json!({"finding_id": "F001"});
        let w = make_witness_with_detail(
            detail.as_object().unwrap().clone(),
            WitnessSource::Fuzz,
            WitnessOutcome::ExitSignal,
            None,
        );
        let (score, reason) =
            score_witness_for_finding(&w, &json!({"id": "F001", "file": "foo.c"}));
        assert_eq!(score, 10);
        assert_eq!(reason, "exact finding-id match");
    }

    #[test]
    fn test_score_cwe_plus_file() {
        // Python: score=7, reason="cwe + file match"
        let detail = json!({"cwe_id": "CWE-120", "file_path": "bar.c"});
        let w = make_witness_with_detail(
            detail.as_object().unwrap().clone(),
            WitnessSource::Fuzz,
            WitnessOutcome::ExitSignal,
            None,
        );
        let (score, reason) = score_witness_for_finding(
            &w,
            &json!({"cwe_id": "CWE-120", "file": "bar.c"}),
        );
        assert_eq!(score, 7);
        assert_eq!(reason, "cwe + file match");
    }

    #[test]
    fn test_score_file_only() {
        // Python: score=4, reason="file match"
        let detail = json!({"file_path": "baz.c"});
        let w = make_witness_with_detail(
            detail.as_object().unwrap().clone(),
            WitnessSource::Fuzz,
            WitnessOutcome::ExitSignal,
            None,
        );
        let (score, reason) = score_witness_for_finding(&w, &json!({"file": "baz.c"}));
        assert_eq!(score, 4);
        assert_eq!(reason, "file match");
    }

    #[test]
    fn test_score_binary_hash() {
        // Python: score=2, reason="same target binary (hash-pending)"
        let mut w = plain_fuzz_exit();
        w.target_binary_hash = Some("x".repeat(64));
        let (score, reason) = score_witness_for_finding(
            &w,
            &json!({"feasibility": {"binary_path": "/bin/test"}}),
        );
        assert_eq!(score, 2);
        assert_eq!(reason, "same target binary (hash-pending)");
    }

    #[test]
    fn test_score_no_signal() {
        // Python: score=0, reason="no structured signal"
        let w = plain_fuzz_exit();
        let (score, reason) = score_witness_for_finding(&w, &json!({"id": "F999"}));
        assert_eq!(score, 0);
        assert_eq!(reason, "no structured signal");
    }

    // -- Golden: best_match_for_finding --

    #[test]
    fn test_best_match_picks_highest_score() {
        // Python: two witnesses, exact-id wins over file match
        // best.score=10, best.reason="exact finding-id match"
        // best.witness.source = "llm_emit_run"
        let w1 = {
            let detail = json!({"finding_id": "F001"});
            let mut w = Witness::new(
                VALID_HASH.to_string(),
                WitnessSource::LlmEmitRun,
                WitnessOutcome::SanitizerReport,
            )
            .unwrap();
            w.outcome_detail = detail.as_object().unwrap().clone().into_iter().collect();
            w
        };
        let w2 = {
            let detail = json!({"file_path": "foo.c"});
            let mut w = Witness::new(
                VALID_HASH_B.to_string(),
                WitnessSource::Fuzz,
                WitnessOutcome::ExitSignal,
            )
            .unwrap();
            w.outcome_detail = detail.as_object().unwrap().clone().into_iter().collect();
            w
        };
        let witnesses = vec![(None, w1), (None, w2)];
        let best = best_match_for_finding(witnesses, &json!({"id": "F001", "file": "foo.c"}))
            .unwrap();
        assert_eq!(best.score, 10);
        assert_eq!(best.reason, "exact finding-id match");
        assert_eq!(best.witness.source, WitnessSource::LlmEmitRun);
        assert!(best.is_real());
    }

    #[test]
    fn test_best_match_no_signal_returns_none() {
        // Python: best_match_for_finding(...) → None
        let witnesses = vec![(None, plain_fuzz_exit())];
        let result = best_match_for_finding(witnesses, &json!({"id": "ZZZZ"}));
        assert!(result.is_none());
    }

    #[test]
    fn test_best_match_tie_break_source_priority() {
        // Two witnesses with same score; LLM_EMIT_RUN beats FUZZ.
        let finding = json!({"file": "shared.c"});

        let w_fuzz = {
            let detail = json!({"file_path": "shared.c"});
            let mut w = Witness::new(
                VALID_HASH.to_string(),
                WitnessSource::Fuzz,
                WitnessOutcome::ExitSignal,
            )
            .unwrap();
            w.outcome_detail = detail.as_object().unwrap().clone().into_iter().collect();
            w
        };
        let w_llm = {
            let detail = json!({"file_path": "shared.c"});
            let mut w = Witness::new(
                VALID_HASH_B.to_string(),
                WitnessSource::LlmEmitRun,
                WitnessOutcome::ExitSignal,
            )
            .unwrap();
            w.outcome_detail = detail.as_object().unwrap().clone().into_iter().collect();
            w
        };
        let witnesses = vec![(None, w_fuzz), (None, w_llm)];
        let best = best_match_for_finding(witnesses, &finding).unwrap();
        assert_eq!(best.witness.source, WitnessSource::LlmEmitRun);
    }

    #[test]
    fn test_best_match_tie_break_outcome_richness() {
        // Two witnesses same score and source; SANITIZER_REPORT beats EXIT_SIGNAL.
        let finding = json!({"file": "vuln.c"});

        let w_signal = {
            let detail = json!({"file_path": "vuln.c"});
            let mut w = Witness::new(
                VALID_HASH.to_string(),
                WitnessSource::Fuzz,
                WitnessOutcome::ExitSignal,
            )
            .unwrap();
            w.outcome_detail = detail.as_object().unwrap().clone().into_iter().collect();
            w
        };
        let w_san = {
            let detail = json!({"file_path": "vuln.c"});
            let mut w = Witness::new(
                VALID_HASH_B.to_string(),
                WitnessSource::Fuzz,
                WitnessOutcome::SanitizerReport,
            )
            .unwrap();
            w.outcome_detail = detail.as_object().unwrap().clone().into_iter().collect();
            w
        };
        let witnesses = vec![(None, w_signal), (None, w_san)];
        let best = best_match_for_finding(witnesses, &finding).unwrap();
        assert_eq!(best.witness.observed_outcome, WitnessOutcome::SanitizerReport);
    }

    #[test]
    fn test_witness_match_is_real_false_at_zero() {
        // is_real() mirrors Python's property
        let w = WitnessMatch {
            witness: plain_fuzz_exit(),
            store_root: None,
            score: 0,
            reason: "no structured signal".to_string(),
        };
        assert!(!w.is_real());
    }
}
