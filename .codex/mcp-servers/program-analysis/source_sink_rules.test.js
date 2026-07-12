"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function ruleById(id) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `expected rule ${id} to exist`);
  return rule;
}

function fires(rule, text) {
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(text);
}

test("js.ejs.render fires on ejs.render/compile", () => {
  const rule = ruleById("js.ejs.render");
  assert.equal(rule.cwe, "CWE-1336");
  assert.ok(fires(rule, "ejs.render(req.query.tpl, data);"));
  assert.ok(fires(rule, "const fn = ejs.compile(userTemplate);"));
  assert.ok(!fires(rule, "renderEjsView(data);"));
});

test("js.pug.render fires on pug.render/compile", () => {
  const rule = ruleById("js.pug.render");
  assert.equal(rule.cwe, "CWE-1336");
  assert.ok(fires(rule, "pug.render(req.body.template);"));
  assert.ok(fires(rule, "const fn = pug.compile(source);"));
  assert.ok(!fires(rule, "pugRenderHelper(source);"));
});

test("py.jinja2.render_template_string fires on render_template_string(", () => {
  const rule = ruleById("py.jinja2.render_template_string");
  assert.equal(rule.cwe, "CWE-1336");
  assert.ok(
    fires(rule, "return render_template_string(request.args.get('tpl'))"),
  );
  assert.ok(!fires(rule, "return render_template('index.html')"));
});

test("py.jinja2.template_direct fires on jinja2.Template(", () => {
  const rule = ruleById("py.jinja2.template_direct");
  assert.equal(rule.cwe, "CWE-1336");
  assert.ok(fires(rule, "tpl = jinja2.Template(request.form['body'])"));
  assert.ok(!fires(rule, "tpl = string.Template(default_body)"));
});

test("all new CWE-1336 (SSTI) rules are sinks with unique ids and global patterns", () => {
  const sstiRules = RULES.filter((r) => r.cwe === "CWE-1336");
  assert.equal(sstiRules.length, 4);
  const ids = new Set();
  for (const rule of sstiRules) {
    assert.equal(rule.kind, "sink");
    assert.ok(
      rule.pattern.flags.includes("g"),
      `${rule.id} pattern must be global`,
    );
    assert.ok(!ids.has(rule.id), `duplicate rule id ${rule.id}`);
    ids.add(rule.id);
  }
});

test("all rule ids across RULES are globally unique", () => {
  const ids = new Set();
  for (const rule of RULES) {
    assert.ok(!ids.has(rule.id), `duplicate rule id ${rule.id}`);
    ids.add(rule.id);
  }
});
