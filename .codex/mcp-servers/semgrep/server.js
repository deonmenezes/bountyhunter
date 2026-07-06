#!/usr/bin/env node
"use strict";

const { createServer } = require("../lib/mcp_stdio.js");
const { runCommand, notFoundMessage } = require("../lib/run_tool.js");

const SEVERITY_MAP = { ERROR: "high", WARNING: "medium", INFO: "low" };

async function semgrepScan({ path: targetPath, config = "auto", rules }) {
  if (!targetPath) throw new Error("path is required");

  const args = ["--json", "--quiet", "--metrics=off"];
  args.push("--config", rules || config);
  args.push(targetPath);

  const result = await runCommand("semgrep", args, { timeoutMs: 300_000 });
  if (result.notFound) {
    return {
      tool: "semgrep",
      available: false,
      message: notFoundMessage(
        "semgrep",
        "pip install semgrep, or brew install semgrep",
      ),
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    return {
      tool: "semgrep",
      available: true,
      error: `semgrep exited ${result.code} and did not return parseable JSON`,
      stderr: result.stderr.slice(0, 4000),
    };
  }

  const findings = (parsed.results || []).map((r) => ({
    rule_id: r.check_id,
    path: r.path,
    start_line: r.start && r.start.line,
    end_line: r.end && r.end.line,
    severity: SEVERITY_MAP[r.extra && r.extra.severity] || "medium",
    message: r.extra && r.extra.message,
    cwe: r.extra && r.extra.metadata && r.extra.metadata.cwe,
  }));

  return {
    tool: "semgrep",
    available: true,
    candidate_count: findings.length,
    findings,
    scan_errors: (parsed.errors || []).map((e) => e.message).slice(0, 20),
  };
}

createServer({
  name: "mantis-semgrep",
  version: "0.1.0",
  tools: [
    {
      name: "semgrep_scan",
      description:
        "High-recall SAST scan with semgrep. Emits `candidate` findings for the Detect stage -- do not self-censor false positives here, that is the Validate stage's job.",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "File or directory to scan (read-only).",
          },
          config: {
            type: "string",
            description:
              'Semgrep --config value, e.g. "auto", "p/owasp-top-ten", or a local ruleset path. Defaults to "auto".',
          },
          rules: {
            type: "string",
            description: "Alias for config; takes precedence if set.",
          },
        },
        required: ["path"],
      },
      handler: semgrepScan,
    },
  ],
});
