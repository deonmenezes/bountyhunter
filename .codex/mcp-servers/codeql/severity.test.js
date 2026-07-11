"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { buildRuleSeverityIndex, severityForResult } = require("./severity.js");

function run(rules, results) {
  return { tool: { driver: { rules } }, results };
}

test("prefers the rule's security-severity score over SARIF level", () => {
  const r = run(
    [{ id: "js/sql-injection", properties: { "security-severity": "9.8" } }],
    [{ ruleId: "js/sql-injection", level: "warning" }],
  );
  const index = buildRuleSeverityIndex(r);
  assert.equal(severityForResult(r.results[0], index), "critical");
});

test("buckets security-severity at the documented thresholds", () => {
  const cases = [
    ["9.8", "critical"],
    ["7.2", "high"],
    ["5.5", "medium"],
    ["2.0", "low"],
  ];
  for (const [score, expected] of cases) {
    const r = run(
      [{ id: "rule-x", properties: { "security-severity": score } }],
      [{ ruleId: "rule-x", level: "note" }],
    );
    const index = buildRuleSeverityIndex(r);
    assert.equal(severityForResult(r.results[0], index), expected);
  }
});

test("falls back to problem.severity when security-severity is absent", () => {
  const r = run(
    [{ id: "rule-y", properties: { "problem.severity": "recommendation" } }],
    [{ ruleId: "rule-y", level: "warning" }],
  );
  const index = buildRuleSeverityIndex(r);
  assert.equal(severityForResult(r.results[0], index), "low");
});

test("falls back to SARIF level when the rule isn't found at all", () => {
  const r = run([], [{ ruleId: "unknown-rule", level: "error" }]);
  const index = buildRuleSeverityIndex(r);
  assert.equal(severityForResult(r.results[0], index), "high");
});

test("defaults a missing level like SARIF itself defaults to warning", () => {
  const r = run([], [{ ruleId: "unknown-rule" }]);
  const index = buildRuleSeverityIndex(r);
  assert.equal(severityForResult(r.results[0], index), "medium");
});

test("severityFromSarifLevel falls back to info for a genuinely unknown level", () => {
  const { severityFromSarifLevel } = require("./severity.js");
  assert.equal(severityFromSarifLevel("none"), "info");
});

test("reads rules from tool.extensions[].rules too", () => {
  const r = {
    tool: {
      driver: { rules: [] },
      extensions: [
        {
          rules: [
            { id: "ext-rule", properties: { "security-severity": "8.0" } },
          ],
        },
      ],
    },
    results: [{ ruleId: "ext-rule", level: "note" }],
  };
  const index = buildRuleSeverityIndex(r);
  assert.equal(severityForResult(r.results[0], index), "high");
});
