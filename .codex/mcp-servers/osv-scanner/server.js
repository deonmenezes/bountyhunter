#!/usr/bin/env node
"use strict";

const { createServer } = require("../lib/mcp_stdio.js");
const { runCommand, notFoundMessage } = require("../lib/run_tool.js");

async function osvScan({ path: targetPath, offline = false }) {
  if (!targetPath) throw new Error("path is required");

  const args = ["--json", "-r"];
  if (offline) args.push("--offline", "--download-offline-databases");
  args.push(targetPath);

  const result = await runCommand("osv-scanner", args, { timeoutMs: 300_000 });
  if (result.notFound) {
    return {
      tool: "osv-scanner",
      available: false,
      message: notFoundMessage(
        "osv-scanner",
        "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest, or brew install osv-scanner",
      ),
    };
  }

  // osv-scanner exits non-zero when vulnerabilities are found; only treat it
  // as a hard failure if stdout isn't parseable JSON at all.
  let parsed;
  try {
    parsed = JSON.parse(result.stdout || "{}");
  } catch {
    return {
      tool: "osv-scanner",
      available: true,
      error: `osv-scanner exited ${result.code} and did not return parseable JSON`,
      stderr: result.stderr.slice(0, 4000),
    };
  }

  const findings = [];
  for (const src of parsed.results || []) {
    for (const pkg of src.packages || []) {
      for (const vuln of pkg.vulnerabilities || []) {
        findings.push({
          source_path: src.source && src.source.path,
          ecosystem: pkg.package && pkg.package.ecosystem,
          package: pkg.package && pkg.package.name,
          version: pkg.package && pkg.package.version,
          vuln_id: vuln.id,
          summary: vuln.summary,
          severity:
            (vuln.database_specific && vuln.database_specific.severity) ||
            "unknown",
          aliases: vuln.aliases || [],
        });
      }
    }
  }

  return {
    tool: "osv-scanner",
    available: true,
    candidate_count: findings.length,
    findings,
  };
}

createServer({
  name: "mantis-osv-scanner",
  version: "0.1.0",
  tools: [
    {
      name: "osv_scan",
      description:
        "SCA scan for known-vulnerable dependencies via osv-scanner, matched against the OSV database. Emits `candidate` findings keyed by package/version -- reachability/exploitability still needs the Validate stage.",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description:
              "Directory to scan recursively for dependency manifests/lockfiles.",
          },
          offline: {
            type: "boolean",
            description:
              "Use a local offline vulnerability DB instead of querying the network.",
          },
        },
        required: ["path"],
      },
      handler: osvScan,
    },
  ],
});
