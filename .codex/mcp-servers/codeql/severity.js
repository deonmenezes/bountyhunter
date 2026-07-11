"use strict";

/**
 * Normalizes a CodeQL SARIF result into the info/low/medium/high/critical
 * severity vocabulary that mantis_findings requires (see findings/server.js
 * VALID_SEVERITIES). Every other Detect-stage server (semgrep, bandit,
 * trivy) already maps its tool-native severity into that vocabulary;
 * codeql_analyze was the one holdout, returning only the raw SARIF `level`
 * (error/warning/note) -- not a legal finding severity, and coarser than
 * CodeQL's own per-rule `security-severity` CVSS-like score. Split into its
 * own module (no side effects) so it's unit-testable without importing
 * server.js, which starts listening on stdin as soon as it's required.
 */

// Bucket boundaries follow GitHub's own security-severity -> criticality
// mapping (docs.github.com/code-security/code-scanning).
function severityFromSecurityScore(score) {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return null;
}

function severityFromSarifLevel(level) {
  if (level === "error") return "high";
  if (level === "warning") return "medium";
  if (level === "note") return "low";
  return "info";
}

// SARIF keys each result's rule by id, and defines the rule (with its
// security-severity property) once per run under tool.driver.rules and/or
// tool.extensions[].rules -- index them so each result can look its rule up.
function buildRuleSeverityIndex(run) {
  const index = new Map();
  const collect = (rules) => {
    for (const rule of rules || []) {
      const props = rule.properties || {};
      const rawScore = props["security-severity"];
      const score = rawScore === undefined ? NaN : Number.parseFloat(rawScore);
      index.set(rule.id, {
        securitySeverity: Number.isFinite(score) ? score : null,
        problemSeverity: props["problem.severity"] || null,
      });
    }
  };
  collect(run.tool && run.tool.driver && run.tool.driver.rules);
  for (const ext of (run.tool && run.tool.extensions) || []) {
    collect(ext.rules);
  }
  return index;
}

function severityForResult(result_, ruleSeverityIndex) {
  const rule = ruleSeverityIndex.get(result_.ruleId);
  if (rule) {
    if (rule.securitySeverity !== null) {
      const bucket = severityFromSecurityScore(rule.securitySeverity);
      if (bucket) return bucket;
    }
    if (rule.problemSeverity === "error") return "high";
    if (rule.problemSeverity === "warning") return "medium";
    if (rule.problemSeverity === "recommendation") return "low";
  }
  return severityFromSarifLevel(result_.level || "warning");
}

module.exports = {
  severityFromSecurityScore,
  severityFromSarifLevel,
  buildRuleSeverityIndex,
  severityForResult,
};
