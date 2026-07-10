"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function matchesAny(ruleId, content) {
  const rule = RULES.find((r) => r.id === ruleId);
  assert.ok(rule, `no rule registered with id ${ruleId}`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(content);
}

test("js.sql.template_literal_query catches interpolated template-literal queries", () => {
  assert.equal(
    matchesAny(
      "js.sql.template_literal_query",
      "db.query(`SELECT * FROM users WHERE id = ${id}`)",
    ),
    true,
  );
});

test("js.sql.string_concat_query catches concatenated SQL strings", () => {
  assert.equal(
    matchesAny(
      "js.sql.string_concat_query",
      "connection.query('SELECT * FROM users WHERE id = ' + userId)",
    ),
    true,
  );
});

test("js sql sinks do not flag parameterized queries", () => {
  const safe = "pool.query('SELECT * FROM users WHERE id = $1', [userId])";
  assert.equal(matchesAny("js.sql.template_literal_query", safe), false);
  assert.equal(matchesAny("js.sql.string_concat_query", safe), false);
});

test("py.sql.fstring_execute catches f-string execute calls", () => {
  assert.equal(
    matchesAny(
      "py.sql.fstring_execute",
      'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    ),
    true,
  );
});

test("py.sql.format_execute catches %-formatted and concatenated execute calls", () => {
  assert.equal(
    matchesAny(
      "py.sql.format_execute",
      'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
    ),
    true,
  );
});

test("py sql sinks do not flag parameterized execute calls", () => {
  const safe =
    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))';
  assert.equal(matchesAny("py.sql.fstring_execute", safe), false);
  assert.equal(matchesAny("py.sql.format_execute", safe), false);
});

test("go.sql.sprintf_query catches Sprintf-built queries", () => {
  assert.equal(
    matchesAny(
      "go.sql.sprintf_query",
      'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))',
    ),
    true,
  );
});

test("go sql sink does not flag parameterized queries", () => {
  const safe = 'db.Query("SELECT * FROM users WHERE id = ?", id)';
  assert.equal(matchesAny("go.sql.sprintf_query", safe), false);
});
