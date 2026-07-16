#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createServer } = require("../lib/mcp_stdio.js");
const { runCommand, notFoundMessage } = require("../lib/run_tool.js");

const CODEQL_NOT_FOUND = notFoundMessage(
  "codeql",
  "download the CodeQL CLI bundle from github.com/github/codeql-cli-binaries and put it on PATH",
);

// SARIF's `level` vocabulary (error/warning/note/none, SARIF 2.1.0 §3.27.10)
// is not the findings spine's severity vocabulary (info/low/medium/high/
// critical, see .codex/mcp-servers/findings/server.js VALID_SEVERITIES).
// Passing SARIF levels straight through made every codeql-sourced candidate
// fail finding_create's severity check -- the same class of bug already
// fixed for semgrep/bandit/trivy/osv-scanner's own SEVERITY_MAPs.
const SARIF_LEVEL_SEVERITY_MAP = {
  error: "high",
  warning: "medium",
  note: "low",
  none: "info",
};

function normalizeSeverity(level) {
  return SARIF_LEVEL_SEVERITY_MAP[level] || "medium";
}

async function codeqlCreateDatabase({
  source_root: sourceRoot,
  language,
  database_path: databasePath,
}) {
  if (!sourceRoot || !language || !databasePath) {
    throw new Error("source_root, language, and database_path are required");
  }

  const result = await runCommand(
    "codeql",
    [
      "database",
      "create",
      databasePath,
      `--language=${language}`,
      `--source-root=${sourceRoot}`,
      "--overwrite",
    ],
    { timeoutMs: 600_000 },
  );
  if (result.notFound)
    return { tool: "codeql", available: false, message: CODEQL_NOT_FOUND };

  return {
    tool: "codeql",
    available: true,
    step: "create_database",
    ok: result.code === 0,
    database_path: databasePath,
    stderr: result.code === 0 ? undefined : result.stderr.slice(0, 4000),
  };
}

async function codeqlAnalyze({
  database_path: databasePath,
  query_suite: querySuite = "security-extended",
}) {
  if (!databasePath) throw new Error("database_path is required");

  const outputPath = path.join(
    os.tmpdir(),
    `mantis-codeql-${process.pid}-${Date.now()}.sarif`,
  );
  const result = await runCommand(
    "codeql",
    [
      "database",
      "analyze",
      databasePath,
      querySuite,
      "--format=sarifv2.1.0",
      `--output=${outputPath}`,
      "--download",
    ],
    { timeoutMs: 900_000 },
  );
  if (result.notFound)
    return { tool: "codeql", available: false, message: CODEQL_NOT_FOUND };

  if (result.code !== 0 || !fs.existsSync(outputPath)) {
    return {
      tool: "codeql",
      available: true,
      step: "analyze",
      ok: false,
      error: `codeql database analyze exited ${result.code}`,
      stderr: result.stderr.slice(0, 4000),
    };
  }

  let sarif;
  try {
    sarif = JSON.parse(fs.readFileSync(outputPath, "utf8"));
  } finally {
    fs.rmSync(outputPath, { force: true });
  }

  const findings = [];
  for (const run of sarif.runs || []) {
    for (const result_ of run.results || []) {
      const loc =
        result_.locations &&
        result_.locations[0] &&
        result_.locations[0].physicalLocation;
      findings.push({
        rule_id: result_.ruleId,
        severity: normalizeSeverity(result_.level),
        message: result_.message && result_.message.text,
        path: loc && loc.artifactLocation && loc.artifactLocation.uri,
        start_line: loc && loc.region && loc.region.startLine,
      });
    }
  }

  return {
    tool: "codeql",
    available: true,
    step: "analyze",
    ok: true,
    candidate_count: findings.length,
    findings,
  };
}

createServer({
  name: "mantis-codeql",
  version: "0.1.0",
  tools: [
    {
      name: "codeql_create_database",
      description:
        "Build a CodeQL database from a source tree (required once before codeql_analyze).",
      inputSchema: {
        type: "object",
        properties: {
          source_root: {
            type: "string",
            description: "Read-only path to the source tree to index.",
          },
          language: {
            type: "string",
            description:
              "CodeQL language id, e.g. javascript, python, go, java.",
          },
          database_path: {
            type: "string",
            description:
              "Output path for the CodeQL database (will be created/overwritten).",
          },
        },
        required: ["source_root", "language", "database_path"],
      },
      handler: codeqlCreateDatabase,
    },
    {
      name: "codeql_analyze",
      description:
        "Run CodeQL query-suite analysis (default security-extended) against a database built by codeql_create_database. Emits `candidate` SAST findings with dataflow-backed rule IDs; `severity` is normalized from SARIF level (error/warning/note/none) to the shared info/low/medium/high/critical vocabulary used by finding_create.",
      inputSchema: {
        type: "object",
        properties: {
          database_path: {
            type: "string",
            description:
              "Path to a database produced by codeql_create_database.",
          },
          query_suite: {
            type: "string",
            description:
              'CodeQL query suite name or path, e.g. "security-extended" or "security-and-quality". Defaults to security-extended.',
          },
        },
        required: ["database_path"],
      },
      handler: codeqlAnalyze,
    },
  ],
});
