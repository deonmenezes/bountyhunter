#!/usr/bin/env node
'use strict';

const { createServer } = require('../lib/mcp_stdio.js');
const { runCommand, notFoundMessage } = require('../lib/run_tool.js');

/**
 * Mantis bandit server (PRD section 6 SAST/code catalog). Python-specific SAST
 * to complement semgrep's breadth. Degrades gracefully: if bandit isn't
 * installed it reports `available: false` rather than fabricating results.
 */

const SEVERITY_MAP = { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

async function banditScan({ path: targetPath, confidence = 'low' }) {
  if (!targetPath) throw new Error('path is required');

  // -r recurse, -f json machine output, -q quiet, -ll/-i filter by confidence.
  const args = ['-r', '-f', 'json', '-q', targetPath];
  if (confidence === 'high') args.push('-iii');
  else if (confidence === 'medium') args.push('-ii');

  const result = await runCommand('bandit', args, { timeoutMs: 300_000 });
  if (result.notFound) {
    return { tool: 'bandit', available: false, message: notFoundMessage('bandit', 'pip install bandit') };
  }

  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    return {
      tool: 'bandit',
      available: true,
      error: `bandit exited ${result.code} and did not return parseable JSON`,
      stderr: result.stderr.slice(0, 4000),
    };
  }

  const findings = (parsed.results || []).map((r) => ({
    rule_id: r.test_id,
    test_name: r.test_name,
    path: r.filename,
    start_line: r.line_number,
    severity: SEVERITY_MAP[r.issue_severity] || 'medium',
    confidence: (r.issue_confidence || '').toLowerCase(),
    message: r.issue_text,
    cwe: r.issue_cwe && r.issue_cwe.id ? `CWE-${r.issue_cwe.id}` : null,
  }));

  return {
    tool: 'bandit',
    available: true,
    candidate_count: findings.length,
    findings,
  };
}

createServer({
  name: 'mantis-bandit',
  version: '0.1.0',
  tools: [
    {
      name: 'bandit_scan',
      description:
        'Python-specific SAST with bandit. Emits `candidate` findings for the Detect stage; complements semgrep for Python targets. Do not treat bandit severity/confidence as final severity -- that is Validate\'s job.',
      inputSchema: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'File or directory of Python source to scan (read-only).' },
          confidence: {
            type: 'string',
            enum: ['low', 'medium', 'high'],
            description: 'Minimum confidence to report. Default "low" for full recall during a first sweep.',
          },
        },
        required: ['path'],
      },
      handler: banditScan,
    },
  ],
});
