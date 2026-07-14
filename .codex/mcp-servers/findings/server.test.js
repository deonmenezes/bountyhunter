"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

// server.js starts an MCP stdio server as a side effect of being required and
// resolves its data dir relative to __dirname, so it can't be require()'d
// directly in a unit test. This writes a patched copy next to the real file
// (so its `require("../lib/mcp_stdio.js")` still resolves), pointed at a
// throwaway data dir instead of the real (gitignored) .codex/findings/ event
// log, with the createServer() call stripped so loading it doesn't start a
// stdio server and hang the test process.
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

function makeCandidate(findingCreate) {
  return findingCreate({
    vuln_class: "sql-injection",
    claim: "unsanitized query built from request.args",
  });
}

test("a single out-of-range axis no longer forces SUBMIT", () => {
  const { findingCreate, findingUpdate } = loadServerWithTempDataDir();
  const created = makeCandidate(findingCreate);

  // Every other axis at 0; only `impact` is wildly out of bounds. Before the
  // fix this summed to a total >= 40 and forced a SUBMIT disposition.
  assert.throws(
    () =>
      findingUpdate({
        id: created.id,
        grade: {
          impact: 1000,
          proof: 0,
          severity_accuracy: 0,
          chain: 0,
          report_quality: 0,
        },
      }),
    /grade\.impact must be within 0-30/,
  );
});

test("a negative axis value is rejected", () => {
  const { findingCreate, findingUpdate } = loadServerWithTempDataDir();
  const created = makeCandidate(findingCreate);

  assert.throws(
    () => findingUpdate({ id: created.id, grade: { proof: -5 } }),
    /grade\.proof must be within 0-25/,
  );
});

test("a non-numeric axis value is rejected", () => {
  const { findingCreate, findingUpdate } = loadServerWithTempDataDir();
  const created = makeCandidate(findingCreate);

  assert.throws(
    () => findingUpdate({ id: created.id, grade: { chain: "high" } }),
    /grade\.chain must be a finite number/,
  );
});

test("an in-bounds grade on every axis still computes total + disposition", () => {
  const { findingCreate, findingUpdate } = loadServerWithTempDataDir();
  const created = makeCandidate(findingCreate);

  const updated = findingUpdate({
    id: created.id,
    grade: {
      impact: 30,
      proof: 25,
      severity_accuracy: 15,
      chain: 15,
      report_quality: 15,
    },
  });
  assert.equal(updated.finding.grade.total, 100);
  assert.equal(updated.disposition, "SUBMIT");
});

test("axes at their exact documented ceiling are accepted (boundary, not off-by-one)", () => {
  const { findingCreate, findingUpdate } = loadServerWithTempDataDir();
  const created = makeCandidate(findingCreate);

  const updated = findingUpdate({
    id: created.id,
    grade: {
      impact: 30,
      proof: 0,
      severity_accuracy: 0,
      chain: 0,
      report_quality: 0,
    },
  });
  assert.equal(updated.finding.grade.total, 30);
  assert.equal(updated.disposition, "HOLD");
});

test("omitted axes still default to 0 without tripping validation", () => {
  const { findingCreate, findingUpdate } = loadServerWithTempDataDir();
  const created = makeCandidate(findingCreate);

  const updated = findingUpdate({
    id: created.id,
    grade: { impact: 10 },
  });
  assert.equal(updated.finding.grade.total, 10);
  assert.equal(updated.disposition, "SKIP");
});
