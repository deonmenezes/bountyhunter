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

test("js.dom.innerhtml fires on real assignment sinks", () => {
  const r = rule("js.dom.innerhtml");
  assert.equal(matches(r, "el.innerHTML = userInput;"), true);
  assert.equal(matches(r, "el.outerHTML = userInput;"), true);
  assert.equal(matches(r, "el.innerHTML += extra;"), true);
  assert.equal(matches(r, "  node.innerHTML=payload"), true);
});

test("js.dom.innerhtml does not fire on equality comparisons", () => {
  const r = rule("js.dom.innerhtml");
  assert.equal(matches(r, 'if (el.innerHTML == "") { }'), false);
  assert.equal(matches(r, "if (el.innerHTML === safe) { }"), false);
  assert.equal(matches(r, "if (el.outerHTML !== previous) { }"), false);
  assert.equal(matches(r, "assert.equal(el.innerHTML, expected);"), false);
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
