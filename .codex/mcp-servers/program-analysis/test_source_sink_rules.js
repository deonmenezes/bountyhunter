#!/usr/bin/env node
"use strict";

/**
 * Lightweight smoke test for source_sink_rules.js -- no test framework
 * dependency, run with `node test_source_sink_rules.js`.
 *
 * Covers the SQL-injection sink rules (CWE-89) added for js/py/go: each
 * must fire on an unparameterized query built from string concat/format,
 * and must NOT fire on the equivalent parameterized-query call, so the
 * heuristic stays high-signal instead of flagging every DB call.
 */
const assert = require("node:assert");
const { RULES } = require("./source_sink_rules.js");

function matches(ruleId, content) {
  const rule = RULES.find((r) => r.id === ruleId);
  assert(rule, `no rule registered with id ${ruleId}`);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(content);
}

const cases = [
  // [ruleId, vulnerableSnippet, safeSnippet]
  [
    "js.sql.query_template_literal",
    "db.query(`SELECT * FROM users WHERE id = ${id}`)",
    "db.query('SELECT * FROM users WHERE id = ?', [id])",
  ],
  [
    "js.sql.query_string_concat",
    'connection.query("SELECT * FROM users WHERE id = " + id)',
    "connection.query('SELECT * FROM users WHERE id = ?', [id])",
  ],
  [
    "py.sql.execute_fstring",
    'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
  ],
  [
    "py.sql.execute_percent_or_concat",
    'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
  ],
  [
    "py.sql.execute_format_call",
    'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))',
    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
  ],
  [
    "go.sql.query_concat",
    'db.Query("SELECT * FROM users WHERE id = " + id)',
    'db.Query("SELECT * FROM users WHERE id = $1", id)',
  ],
  [
    "go.sql.query_sprintf",
    'db.Exec(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))',
    'db.Exec("SELECT * FROM users WHERE id = $1", id)',
  ],
];

let failures = 0;
for (const [ruleId, vulnerable, safe] of cases) {
  if (!matches(ruleId, vulnerable)) {
    failures++;
    console.error(`FAIL ${ruleId}: expected to match vulnerable snippet`);
  }
  if (matches(ruleId, safe)) {
    failures++;
    console.error(
      `FAIL ${ruleId}: unexpectedly matched parameterized/safe snippet`,
    );
  }
}

if (failures > 0) {
  console.error(`${failures} failure(s)`);
  process.exit(1);
}
console.log(`ok - ${cases.length} SQL-injection sink rules verified`);
