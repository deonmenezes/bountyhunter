//! Convert Semgrep results to MANTISHACK findings format.
//! Faithful port of `packages/semgrep/findings.py`.

use std::collections::HashMap;

use crate::models::SemgrepResult;

/// Convert Semgrep results to MANTISHACK `findings.json` entries.
///
/// Each Semgrep finding becomes a finding with `origin: "semgrep"`. The
/// `vuln_type` is left blank — the caller (typically the agentic pipeline)
/// maps from `rule_id` to a CWE/vuln_type via core/sarif normalisation.
///
/// Mirrors Python `to_findings`.
pub fn to_findings(results: &[SemgrepResult]) -> Vec<serde_json::Value> {
    let mut findings = Vec::new();
    // Python: counters: Dict[str, int] = defaultdict(int)
    let mut counters: HashMap<String, usize> = HashMap::new();

    for result in results {
        // Python: run_label = result.name or "semgrep"
        let run_label = if result.name.is_empty() {
            "semgrep".to_string()
        } else {
            result.name.clone()
        };

        for f in &result.findings {
            let count = counters.entry(run_label.clone()).or_insert(0);
            *count += 1;

            // Python: f.message or f"Match for {f.rule_id}"
            let description = if f.message.is_empty() {
                format!("Match for {}", f.rule_id)
            } else {
                f.message.clone()
            };

            findings.push(serde_json::json!({
                "id":          format!("SEMGREP-{}-{}", run_label, count),
                "file":        f.file,
                "line":        f.line,
                "function":    "",
                "vuln_type":   "",
                "confidence":  "medium",
                "origin":      "semgrep",
                "rule":        f.rule_id,
                "level":       f.level,
                "description": description,
            }));
        }
    }
    findings
}
