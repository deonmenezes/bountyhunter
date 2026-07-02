//! Operator-facing SCA pipeline-phase descriptions — Rust port of
//! `packages/sca/pipeline_phases.py`.

/// One-line description for a named pipeline phase (`describe_phase`); `None`
/// for an unknown phase.
pub fn describe_phase(name: &str) -> Option<&'static str> {
    Some(match name {
        "discovery" => "discovering manifests + parsing dependencies",
        "cascade" => "expanding transitive dependencies",
        "hygiene" => "evaluating dependency hygiene heuristics",
        "supply-chain" => "evaluating supply-chain risk heuristics",
        "license" => "enriching + evaluating license metadata",
        "osv" => "querying OSV / KEV / EPSS for vulnerability advisories",
        "reach" => "scanning project source for reachable use of vulnerable deps",
        "findings" => "building vulnerability findings",
        "llm-review" => "running LLM behavioural review on supply-chain + vuln findings",
        "triage" => "running LLM triage ranking",
        "impact-analysis" => "running LLM upgrade-impact analysis",
        "emit" => "writing findings.json / report.md / SBOM / SARIF artefacts",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_descriptions() {
        assert_eq!(describe_phase("osv"), Some("querying OSV / KEV / EPSS for vulnerability advisories"));
        assert_eq!(describe_phase("emit"), Some("writing findings.json / report.md / SBOM / SARIF artefacts"));
        assert_eq!(describe_phase("discovery"), Some("discovering manifests + parsing dependencies"));
        assert_eq!(describe_phase("unknown-phase"), None);
    }
}
