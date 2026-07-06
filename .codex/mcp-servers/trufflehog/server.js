#!/usr/bin/env node
"use strict";

const { createServer } = require("../lib/mcp_stdio.js");
const { runCommand, notFoundMessage } = require("../lib/run_tool.js");

// Never forward raw secret material. Per the Mantis evidence-handling
// contract, findings/evidence/reports must never contain live secrets --
// only enough to prove a match exists and where.
function redact(secret) {
  if (!secret) return "[REDACTED_SECRET]";
  if (secret.length <= 8) return "[REDACTED_SECRET]";
  return `${secret.slice(0, 4)}...[REDACTED ${secret.length} chars]...${secret.slice(-4)}`;
}

async function trufflehogScan({ path: targetPath, only_verified = false }) {
  if (!targetPath) throw new Error("path is required");

  const args = ["filesystem", "--json", "--no-update"];
  if (only_verified) args.push("--only-verified");
  args.push(targetPath);

  const result = await runCommand("trufflehog", args, { timeoutMs: 300_000 });
  if (result.notFound) {
    return {
      tool: "trufflehog",
      available: false,
      message: notFoundMessage(
        "trufflehog",
        "brew install trufflehog, or see github.com/trufflesecurity/trufflehog",
      ),
    };
  }

  const findings = [];
  for (const line of result.stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let entry;
    try {
      entry = JSON.parse(trimmed);
    } catch {
      continue;
    }
    const file =
      entry.SourceMetadata &&
      entry.SourceMetadata.Data &&
      entry.SourceMetadata.Data.Filesystem &&
      entry.SourceMetadata.Data.Filesystem.file;
    findings.push({
      detector: entry.DetectorName,
      verified: !!entry.Verified,
      file,
      redacted_secret: redact(entry.Raw),
    });
  }

  if (findings.length === 0 && result.code !== 0 && result.stderr) {
    return {
      tool: "trufflehog",
      available: true,
      error: `trufflehog exited ${result.code}`,
      stderr: result.stderr.slice(0, 4000),
    };
  }

  return {
    tool: "trufflehog",
    available: true,
    candidate_count: findings.length,
    findings,
  };
}

createServer({
  name: "mantis-trufflehog",
  version: "0.1.0",
  tools: [
    {
      name: "trufflehog_scan",
      description:
        "Secrets scan via trufflehog. Verified secrets (live-checked against the provider) are high-confidence `confirmed` findings; unverified matches are `candidate` leads. Secret material is always redacted in the response.",
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "Directory to scan." },
          only_verified: {
            type: "boolean",
            description:
              "Only report secrets trufflehog could live-verify against the provider.",
          },
        },
        required: ["path"],
      },
      handler: trufflehogScan,
    },
  ],
});
