//! Findings-layer pure helpers — Rust port of the self-contained functions in
//! `packages/sca/findings.py`. The finding-assembly pipeline (`build_vuln_findings`,
//! `_assemble_finding`) depends on the Advisory/Reachability models and stays in
//! Python for now; the severity ranking used by the report layer + CI gates ports
//! here.

/// Rank for a severity string (`_SEVERITY_RANK`). `info`/`none` = 0.
fn severity_rank_lookup(sev: &str) -> Option<i32> {
    match sev {
        "info" | "none" => Some(0),
        "low" => Some(1),
        "medium" => Some(2),
        "high" => Some(3),
        "critical" => Some(4),
        _ => None,
    }
}

/// Return the rank for a severity string (`severity_rank`). Case-insensitive
/// (LLM/hand-edited findings often capitalise); unknown or empty → 0.
pub fn severity_rank(severity: &str) -> i32 {
    if severity.is_empty() {
        return 0;
    }
    severity_rank_lookup(&severity.to_lowercase()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_and_case_insensitivity() {
        assert_eq!(severity_rank("info"), 0);
        assert_eq!(severity_rank("none"), 0);
        assert_eq!(severity_rank("low"), 1);
        assert_eq!(severity_rank("medium"), 2);
        assert_eq!(severity_rank("high"), 3);
        assert_eq!(severity_rank("critical"), 4);
        // Case-insensitive.
        assert_eq!(severity_rank("Critical"), 4);
        assert_eq!(severity_rank("HIGH"), 3);
        assert_eq!(severity_rank("Medium"), 2);
        // Unknown + empty -> 0.
        assert_eq!(severity_rank("bogus"), 0);
        assert_eq!(severity_rank(""), 0);
    }
}
