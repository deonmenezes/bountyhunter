"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matches(id, text) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `no rule registered with id ${id}`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(text);
}

test("py.django.mark_safe flags mark_safe(...) calls", () => {
  assert.equal(
    matches("py.django.mark_safe", "return mark_safe(user_bio)"),
    true,
  );
});

test("py.django.mark_safe does not flag unrelated safe_* helpers", () => {
  assert.equal(
    matches("py.django.mark_safe", "value = safe_lookup(user_bio)"),
    false,
  );
});

test("py.flask.render_template_string flags dynamic template rendering", () => {
  assert.equal(
    matches(
      "py.flask.render_template_string",
      'return render_template_string(f"Hello {name}")',
    ),
    true,
  );
});

test("py.flask.render_template_string does not flag render_template (file-based, no injection surface)", () => {
  assert.equal(
    matches(
      "py.flask.render_template_string",
      'return render_template("hello.html", name=name)',
    ),
    false,
  );
});

test("java.servlet.writer_output flags response.getWriter().print/println", () => {
  assert.equal(
    matches(
      "java.servlet.writer_output",
      'response.getWriter().println(request.getParameter("name"));',
    ),
    true,
  );
  assert.equal(
    matches(
      "java.servlet.writer_output",
      "response.getWriter().print(safeValue);",
    ),
    true,
  );
});

test("java.servlet.writer_output does not flag unrelated writer variables", () => {
  assert.equal(
    matches("java.servlet.writer_output", "logWriter.println(status);"),
    false,
  );
});

test("every rule id is unique", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("every sink rule carries a CWE tag", () => {
  for (const rule of RULES.filter((r) => r.kind === "sink")) {
    assert.ok(rule.cwe, `sink rule ${rule.id} is missing a cwe tag`);
  }
});
