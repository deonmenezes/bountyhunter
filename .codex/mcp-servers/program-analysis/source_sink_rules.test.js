"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matches(ruleId, content) {
  const rule = RULES.find((r) => r.id === ruleId);
  assert.ok(rule, `rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(content);
}

test("js.sql.query_template_interp catches interpolated raw query", () => {
  assert.equal(
    matches(
      "js.sql.query_template_interp",
      "db.query(`SELECT * FROM users WHERE id = ${id}`)",
    ),
    true,
  );
});

test("js.sql.query_template_interp ignores static template literal", () => {
  assert.equal(
    matches(
      "js.sql.query_template_interp",
      "db.query(`SELECT * FROM users WHERE id = 1`)",
    ),
    false,
  );
});

test("js.sql.query_string_concat catches concatenated query", () => {
  assert.equal(
    matches(
      "js.sql.query_string_concat",
      'conn.query("SELECT * FROM users WHERE id = " + userId)',
    ),
    true,
  );
});

test("js.sql.query_string_concat ignores parameterized query", () => {
  assert.equal(
    matches(
      "js.sql.query_string_concat",
      'conn.query("SELECT * FROM users WHERE id = ?", [userId])',
    ),
    false,
  );
});

test("py.sql.execute_fstring catches f-string in execute", () => {
  assert.equal(
    matches(
      "py.sql.execute_fstring",
      'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    ),
    true,
  );
});

test("py.sql.execute_fstring ignores plain parameterized execute", () => {
  assert.equal(
    matches(
      "py.sql.execute_fstring",
      'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    ),
    false,
  );
});

test("py.sql.execute_string_format catches %-formatted query", () => {
  assert.equal(
    matches(
      "py.sql.execute_string_format",
      'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
    ),
    true,
  );
});

test("py.sql.execute_string_format catches .format() query", () => {
  assert.equal(
    matches(
      "py.sql.execute_string_format",
      'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))',
    ),
    true,
  );
});

test("py.sql.execute_string_format ignores parameterized execute", () => {
  assert.equal(
    matches(
      "py.sql.execute_string_format",
      'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    ),
    false,
  );
});

test("go.sql.query_sprintf catches Sprintf-built query", () => {
  assert.equal(
    matches(
      "go.sql.query_sprintf",
      'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))',
    ),
    true,
  );
});

test("go.sql.query_sprintf ignores parameterized query", () => {
  assert.equal(
    matches(
      "go.sql.query_sprintf",
      'db.Query("SELECT * FROM users WHERE id = $1", id)',
    ),
    false,
  );
});
