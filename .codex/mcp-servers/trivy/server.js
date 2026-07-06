#!/usr/bin/env node
"use strict";

const { createServer } = require("../lib/mcp_stdio.js");
const { runCommand, notFoundMessage } = require("../lib/run_tool.js");

/**
 * Mantis trivy server (PRD section 6 SCA/deps + container catalog). Broad
 * composition analysis: vulnerable dependencies, embedded secrets, and IaC
 * misconfigurations over a filesystem path. Complements osv-scanner (SCA) and
 * trufflehog (secrets) with container/IaC coverage. Degrades gracefully.
 */

const SEVERITY_MAP = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

async function trivyScan({
  path: targetPath,
  scanners = "vuln,secret,misconfig",
}) {
  if (!targetPath) throw new Error("path is required");

  const args = [
    "fs",
    "--format",
    "json",
    "--quiet",
    "--scanners",
    scanners,
    targetPath,
  ];

  const result = await runCommand("trivy", args, { timeoutMs: 300_000 });
  if (result.notFound) {
    return {
      tool: "trivy",
      available: false,
      message: notFoundMessage(
        "trivy",
        "brew install trivy, or see aquasecurity/trivy releases",
      ),
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    return {
      tool: "trivy",
      available: true,
      error: `trivy exited ${result.code} and did not return parseable JSON`,
      stderr: result.stderr.slice(0, 4000),
    };
  }

  const vulns = [];
  const misconfigs = [];
  const secrets = [];
  for (const target of parsed.Results || []) {
    for (const v of target.Vulnerabilities || []) {
      vulns.push({
        target: target.Target,
        pkg: v.PkgName,
        installed: v.InstalledVersion,
        fixed: v.FixedVersion || null,
        advisory: v.VulnerabilityID,
        severity: SEVERITY_MAP[v.Severity] || "medium",
        title: v.Title,
      });
    }
    for (const m of target.Misconfigurations || []) {
      misconfigs.push({
        target: target.Target,
        id: m.ID,
        severity: SEVERITY_MAP[m.Severity] || "medium",
        title: m.Title,
        message: m.Message,
      });
    }
    // trivy already redacts the secret value in its Match preview; never echo more.
    for (const s of target.Secrets || []) {
      secrets.push({
        target: target.Target,
        rule_id: s.RuleID,
        severity: SEVERITY_MAP[s.Severity] || "high",
        title: s.Title,
        start_line: s.StartLine,
      });
    }
  }

  return {
    tool: "trivy",
    available: true,
    candidate_count: vulns.length + misconfigs.length + secrets.length,
    vulnerabilities: vulns,
    misconfigurations: misconfigs,
    secrets,
  };
}

createServer({
  name: "mantis-trivy",
  version: "0.1.0",
  tools: [
    {
      name: "trivy_scan",
      description:
        "Composition analysis with trivy: vulnerable dependencies, embedded secrets, and IaC misconfigurations over a path. Emits `candidate` findings for Detect. Secret values are not returned -- only rule/line references. A vulnerable dep being present does not mean the vulnerable path is reachable; that is a separate question for Reachability.",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "Directory to scan (read-only).",
          },
          scanners: {
            type: "string",
            description:
              'Comma-separated trivy scanners. Default "vuln,secret,misconfig". Narrow (e.g. "vuln") to cut noise.',
          },
        },
        required: ["path"],
      },
      handler: trivyScan,
    },
  ],
});
