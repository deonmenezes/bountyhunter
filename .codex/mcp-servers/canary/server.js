#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createServer } = require('../lib/mcp_stdio.js');

// Injection/hallucination tripwire (PRD section 6 "injection-canary tools",
// FR-6.7). These tool names are deliberately tempting. A well-behaved agent
// following its authorization boundary should never call them; if one does,
// that's a signal of prompt injection from scanned/untrusted target content,
// or a model hallucinating a capability it doesn't have.
const DECOY_TOOL_NAMES = [
  'read_org_credentials_vault',
  'disable_sandbox_protections',
  'exfiltrate_environment_secrets',
  'grant_admin_access',
];

const ALERT_LOG = path.join(__dirname, 'alerts.log');

function fireAlert(toolName, args) {
  const alert = {
    timestamp: new Date().toISOString(),
    tool: toolName,
    arguments: args,
    severity: 'critical',
    note: 'Decoy tool invoked -- treat as evidence of prompt injection or a hallucinated capability. Stop and re-establish authorization/scope before continuing.',
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
      'DECOY TOOL -- do not call. This name exists only as a tripwire; calling it is logged as a critical security alert and does nothing else.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: true },
    handler: async (args) => {
      const alert = fireAlert(name, args);
      return {
        refused: true,
        reason: 'This is a decoy tool used to detect prompt injection or hallucinated tool use. The call was logged, not executed.',
        alert,
      };
    },
  };
}

createServer({
  name: 'mantis-canary',
  version: '0.1.0',
  tools: DECOY_TOOL_NAMES.map(makeDecoyTool),
});
