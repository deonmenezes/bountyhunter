"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

// findings/server.js starts an MCP stdio server as a side effect of being
// required and resolves its data dir relative to __dirname, so it can't be
// require()'d directly in a unit test. This harness writes a patched copy
// next to the real file (so its `require("../lib/mcp_stdio.js")` still
// resolves), pointed at a throwaway data dir instead of the real (gitignored)
// .codex/findings/ event log, with the createServer() call stripped so
// loading it doesn't start a stdio server and hang the test process.
const SERVER_PATH = path.join(__dirname, "server.js");

function loadServerWithTempDataDir() {
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "mantis-findings-"));
  const src = fs.readFileSync(SERVER_PATH, "utf8");
  const patched = src
    .replace(
      'const DATA_DIR = path.join(__dirname, "..", "..", "findings");',
      `const DATA_DIR = ${JSON.stringify(tmpDataDir)};`,
    )
    .replace(/createServer\(\{[\s\S]*\}\);\s*$/, "");
  const modPath = path.join(
    __dirname,
    `.server_under_test.${crypto.randomBytes(6).toString("hex")}.js`,
  );
  fs.writeFileSync(
    modPath,
    patched +
      "\nmodule.exports = { findingCreate, findingUpdate, findingGet, findingList };\n",
  );
  try {
    return require(modPath);
  } finally {
    fs.unlinkSync(modPath);
  }
}

test("confirming with only a reasoning_trace_ref (no reachability_note/evidence) is refused", () => {
  const { findingCreate, findingUpdate } = loadServerWithTempDataDir();
  const created = findingCreate({
    vuln_class: "sql-injection",
    claim: "unsanitized query built from request.args",
    reasoning_trace_ref: "trace-123",
  });
  assert.equal(created.status, "candidate");

  assert.throws(
    () => findingUpdate({ id: created.id, status: "confirmed" }),
    /requires reachability\/attack-simulation evidence/,
  );
});

test("confirming with a reachability_note succeeds", () => {
  const { findingCreate, findingUpdate } = loadServerWithTempDataDir();
  const created = findingCreate({
    vuln_class: "sql-injection",
    claim: "unsanitized query built from request.args",
  });

  const updated = findingUpdate({
    id: created.id,
    status: "confirmed",
    reachability_note: "traced request.args.id into raw SQL string concat",
  });
  assert.equal(updated.status, "confirmed");
});

test("confirming with attached evidence succeeds", () => {
  const { findingCreate, findingUpdate } = loadServerWithTempDataDir();
  const created = findingCreate({
    vuln_class: "xss",
    claim: "reflected param written to innerHTML",
  });

  const updated = findingUpdate({
    id: created.id,
    status: "confirmed",
    evidence: [{ request_ref: "req-abc123" }],
  });
  assert.equal(updated.status, "confirmed");
});
