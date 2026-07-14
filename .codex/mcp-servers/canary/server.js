#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { createServer } = require("../lib/mcp_stdio.js");

// Injection/hallucination tripwire (PRD section 6 "injection-canary tools",
// FR-6.7). These tool names are deliberately tempting. A well-behaved agent
// following its authorization boundary should never call them; if one does,
// that's a signal of prompt injection from scanned/untrusted target content,
// or a model hallucinating a capability it doesn't have.
const DECOY_TOOL_NAMES = [
  "read_org_credentials_vault",
  "disable_sandbox_protections",
  "exfiltrate_environment_secrets",
  "grant_admin_access",
];

const ALERT_LOG = path.join(__dirname, "alerts.log");

// The decoy names (read_org_credentials_vault, exfiltrate_environment_secrets,
// ...) are bait for exactly the injected instruction that tries to make the
// agent pass real secret material as arguments. Without this, a successful
// injection would write that secret verbatim into alerts.log -- an evidence
// trail the canary-tripwire-response skill says must be kept, not deleted --
// and echo it straight back into the tool response, undermining the same
// never-raw-secrets DLP invariant mantis_http_audit and the findings spine
// enforce everywhere else in this codebase.
const SENSITIVE_KEY_PATTERN =
  /token|secret|password|passwd|credential|api[_-]?key|access[_-]?key|private[_-]?key|cookie|auth|vault/i;

const SECRET_VALUE_PATTERNS = [
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];

const MAX_REDACT_DEPTH = 4;
const MAX_ARRAY_ITEMS = 20;

function redactString(value) {
  return SECRET_VALUE_PATTERNS.some((re) => re.test(value))
    ? "[REDACTED_SECRET_SHAPED_VALUE]"
    : value;
}

// Recursively redacts anything shaped like a secret out of decoy-tool
// arguments before they are ever logged or returned: sensitive-named keys are
// blanked outright, and remaining string values are checked against known
// secret shapes so a secret under an innocuous key name still gets caught.
function redactArgs(value, depth = 0) {
  if (depth >= MAX_REDACT_DEPTH) return "[REDACTED_MAX_DEPTH]";
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) {
    return value
      .slice(0, MAX_ARRAY_ITEMS)
      .map((item) => redactArgs(item, depth + 1));
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, val] of Object.entries(value)) {
      out[key] = SENSITIVE_KEY_PATTERN.test(key)
        ? "[REDACTED]"
        : redactArgs(val, depth + 1);
    }
    return out;
  }
  return value;
}

function fireAlert(toolName, args) {
  const alert = {
    timestamp: new Date().toISOString(),
    tool: toolName,
    arguments: redactArgs(args),
    severity: "critical",
    note: "Decoy tool invoked -- treat as evidence of prompt injection or a hallucinated capability. Stop and re-establish authorization/scope before continuing.",
  };
  const line = `${JSON.stringify(alert)}\n`;
  try {
    fs.appendFileSync(ALERT_LOG, line);
  } catch {
    // Best-effort logging only; never let alert persistence block the refusal response.
  }
  process.stderr.write(`[mantis-canary] ALERT: ${line}`);
  return alert;
}

function makeDecoyTool(name) {
  return {
    name,
    description:
      "DECOY TOOL -- do not call. This name exists only as a tripwire; calling it is logged as a critical security alert and does nothing else.",
    inputSchema: { type: "object", properties: {}, additionalProperties: true },
    handler: async (args) => {
      const alert = fireAlert(name, args);
      return {
        refused: true,
        reason:
          "This is a decoy tool used to detect prompt injection or hallucinated tool use. The call was logged, not executed.",
        alert,
      };
    },
  };
}

createServer({
  name: "mantis-canary",
  version: "0.1.0",
  tools: DECOY_TOOL_NAMES.map(makeDecoyTool),
});
