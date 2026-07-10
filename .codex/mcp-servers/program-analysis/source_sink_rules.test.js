"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matches(id, text) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `no rule registered with id ${id}`);
  // Rules use a global regex with internal state (lastIndex); test against a
  // fresh copy each call so repeated assertions don't interfere.
  const re = new RegExp(rule.pattern.source, rule.pattern.flags);
  return re.test(text);
}

test("js.proto.dunder_proto_assign flags __proto__ writes", () => {
  assert.equal(
    matches("js.proto.dunder_proto_assign", "obj.__proto__ = value"),
    true,
  );
  assert.equal(
    matches("js.proto.dunder_proto_assign", 'obj["__proto__"] = value'),
    true,
  );
  assert.equal(
    matches("js.proto.dunder_proto_assign", "target[keys[i]] = value"),
    false,
  );
});

test("js.proto.dunder_proto_assign does not flag the denylist-check mitigation", () => {
  assert.equal(
    matches("js.proto.dunder_proto_assign", 'if (key === "__proto__") return;'),
    false,
  );
  assert.equal(
    matches("js.proto.dunder_proto_assign", 'key !== "__proto__"'),
    false,
  );
});

test("js.proto.constructor_prototype_chain flags the constructor.prototype primitive", () => {
  assert.equal(
    matches(
      "js.proto.constructor_prototype_chain",
      "obj.constructor.prototype.polluted = true",
    ),
    true,
  );
  assert.equal(
    matches(
      "js.proto.constructor_prototype_chain",
      'obj["constructor"]["prototype"]["polluted"] = true',
    ),
    true,
  );
  assert.equal(
    matches(
      "js.proto.constructor_prototype_chain",
      "const c = new Constructor();",
    ),
    false,
  );
});

test("js.proto.vulnerable_merge_call flags known-vulnerable deep-merge helpers", () => {
  assert.equal(
    matches("js.proto.vulnerable_merge_call", "_.merge(target, userInput)"),
    true,
  );
  assert.equal(
    matches(
      "js.proto.vulnerable_merge_call",
      "_.defaultsDeep(target, userInput)",
    ),
    true,
  );
  assert.equal(
    matches(
      "js.proto.vulnerable_merge_call",
      "$.extend(true, target, userInput)",
    ),
    true,
  );
  assert.equal(
    matches("js.proto.vulnerable_merge_call", "deepmerge(target, userInput)"),
    true,
  );
  assert.equal(
    matches("js.proto.vulnerable_merge_call", "$.extend(target, userInput)"),
    false,
  );
  assert.equal(
    matches(
      "js.proto.vulnerable_merge_call",
      "Object.assign(target, userInput)",
    ),
    false,
  );
});
