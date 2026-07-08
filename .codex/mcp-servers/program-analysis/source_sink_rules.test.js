"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function rule(id) {
  const found = RULES.find((r) => r.id === id);
  assert.ok(found, `rule ${id} not found`);
  return found;
}

function matches(r, text) {
  r.pattern.lastIndex = 0;
  return r.pattern.test(text);
}

test("js.child_process.exec fires on real child_process calls", () => {
  const r = rule("js.child_process.exec");
  assert.equal(matches(r, "child_process.exec(cmd)"), true);
  assert.equal(matches(r, "cp.execSync(cmd)"), true);
  assert.equal(matches(r, "childProcess.exec(cmd)"), true);
  assert.equal(matches(r, "exec(cmd)"), true);
  assert.equal(matches(r, "execSync(cmd)"), true);
  assert.equal(matches(r, 'require("child_process").exec(cmd)'), true);
  assert.equal(matches(r, "require('child_process').execSync(cmd)"), true);
});

test("js.child_process.exec does not fire on RegExp/Array .exec() member calls", () => {
  const r = rule("js.child_process.exec");
  assert.equal(matches(r, "const m = pattern.exec(str);"), false);
  assert.equal(matches(r, "if (re.exec(line)) { }"), false);
  assert.equal(matches(r, "arr.filter(x => x.exec(y))"), false);
  assert.equal(matches(r, "const ok = /foo/.exec(input);"), false);
});

test("every rule has a unique id", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("every sink rule carries a CWE tag", () => {
  for (const r of RULES.filter((r) => r.kind === "sink")) {
    assert.ok(r.cwe, `sink rule ${r.id} is missing a cwe tag`);
  }
});
