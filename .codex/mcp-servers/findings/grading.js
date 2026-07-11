"use strict";

/**
 * Pure grading logic for the findings spine, split out of server.js so it can
 * be unit-tested without booting the stdio MCP server (server.js calls
 * createServer(...) at module scope, which attaches a stdin listener).
 */

const MEDIUM_PLUS_SEVERITIES = new Set(["medium", "high", "critical"]);

// 5-axis grade -> disposition (PRD section 9, FR-10.1, Appendix C). Per the
// reporter role's documented rubric (.codex/agents/reporter.toml: "SUBMIT
// (>=40 with at least one medium+)"), SUBMIT requires BOTH total>=40 AND a
// severity of at least medium -- a finding that scores high on proof/impact/
// chain/report-quality but has no (or a low) severity should read as HOLD,
// not as ship-worthy.
function gradeToDisposition(grade, severity) {
  if (!grade) return null;
  const total =
    (grade.impact || 0) +
    (grade.proof || 0) +
    (grade.severity_accuracy || 0) +
    (grade.chain || 0) +
    (grade.report_quality || 0);
  let disposition = "SKIP";
  if (total >= 40 && MEDIUM_PLUS_SEVERITIES.has(severity)) {
    disposition = "SUBMIT";
  } else if (total >= 20) {
    disposition = "HOLD";
  }
  return { total, disposition };
}

module.exports = { gradeToDisposition, MEDIUM_PLUS_SEVERITIES };
