"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matches(ruleId, code) {
  const rule = RULES.find((r) => r.id === ruleId);
  assert.ok(rule, `no rule registered with id ${ruleId}`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(code);
}

test("py.yaml.load_unsafe flags a bare yaml.load with no Loader", () => {
  assert.equal(matches("py.yaml.load_unsafe", "yaml.load(user_input)"), true);
});

test("py.yaml.load_unsafe does not flag a single-line SafeLoader call", () => {
  assert.equal(
    matches("py.yaml.load_unsafe", "yaml.load(f, Loader=yaml.SafeLoader)"),
    false,
  );
});

test("py.yaml.load_unsafe does not flag a SafeLoader call wrapped across lines", () => {
  assert.equal(
    matches(
      "py.yaml.load_unsafe",
      "yaml.load(\n    f,\n    Loader=yaml.SafeLoader,\n)",
    ),
    false,
  );
});

test("py.yaml.load_unsafe still flags an unsafe call preceding a safe one", () => {
  // Regression guard: an unbounded dotall lookahead would let the SECOND
  // call's SafeLoader kwarg suppress the flag on the FIRST, unsafe call.
  assert.equal(
    matches(
      "py.yaml.load_unsafe",
      "yaml.load(a)\nyaml.load(b, Loader=yaml.SafeLoader)",
    ),
    true,
  );
});
