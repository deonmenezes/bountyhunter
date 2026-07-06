#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { createServer } = require('../lib/mcp_stdio.js');

/**
 * Mantis findings service -- the tool-owned findings spine (PRD section 9,
 * FR-9.*, FR-11.3). Agents never hand-edit finding state: they go through this
 * server, which owns ids, the schema, lifecycle transitions, and an append-only
 * audit trail. "Evidence is the product": a finding cannot be `confirmed`
 * without a reachability/attack-sim note, and cannot be `rejected` without a
 * cited roadblock (PRD section 5, section 8 "reject discipline").
 *
 * Storage is a single append-only JSONL event log under `.codex/findings/`.
 * Current state is a left-fold over that log, so history is never lost and the
 * run is reconstructable (NFR-9). Zero external dependencies.
 */

const DATA_DIR = path.join(__dirname, '..', '..', 'findings');
const EVENT_LOG = path.join(DATA_DIR, 'events.jsonl');

// Lifecycle: candidate -> confirmed|rejected -> exploited -> fixed -> verified
// (PRD section 5). `rejected` is terminal for that finding id. Detect is
// generous; Validate is ruthless.
const STATUS_TRANSITIONS = {
  candidate: ['confirmed', 'rejected'],
  confirmed: ['exploited', 'fixed', 'rejected'],
  exploited: ['fixed', 'rejected'],
  fixed: ['verified', 'rejected'],
  verified: [],
  rejected: [],
};

const VALID_STATUSES = Object.keys(STATUS_TRANSITIONS);
const VALID_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

// Cheap secret-shaped-string guard so raw credentials never land in a finding
// or evidence blob (PRD section 9 "never raw secrets/tokens/cookies/full
// bodies", section 11 secrets/DLP). This is a backstop, not a full DLP engine.
const SECRET_PATTERNS = [
  /\bAKIA[0-9A-Z]{16}\b/, // AWS access key id
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/, // GitHub tokens
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, // Slack tokens
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/, // PEM private keys
  /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, // JWTs
];

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function nowIso() {
  return new Date().toISOString();
}

function newId() {
  return `MANTIS-${crypto.randomBytes(5).toString('hex')}`;
}

function scanForSecrets(value) {
  const hay = typeof value === 'string' ? value : JSON.stringify(value ?? '');
  return SECRET_PATTERNS.some((re) => re.test(hay));
}

function appendEvent(event) {
  ensureDataDir();
  fs.appendFileSync(EVENT_LOG, `${JSON.stringify(event)}\n`);
}

// Replays the event log into the current finding map. Kept simple and total:
// each event is either a `create` or an `update` keyed by finding id.
function loadState() {
  const findings = new Map();
  if (!fs.existsSync(EVENT_LOG)) return findings;
  const lines = fs.readFileSync(EVENT_LOG, 'utf8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let event;
    try {
      event = JSON.parse(trimmed);
    } catch {
      continue; // Skip a corrupt line rather than losing the whole log.
    }
    if (event.kind === 'create') {
      findings.set(event.finding.id, event.finding);
    } else if (event.kind === 'update') {
      const existing = findings.get(event.id);
      if (!existing) continue;
      const merged = { ...existing, ...event.changes };
      merged.history = [...(existing.history || []), event.history_entry];
      findings.set(event.id, merged);
    }
  }
  return findings;
}

// 5-axis grade -> disposition (PRD section 9, FR-10.1, Appendix C).
function gradeToDisposition(grade) {
  if (!grade) return null;
  const total =
    (grade.impact || 0) +
    (grade.proof || 0) +
    (grade.severity_accuracy || 0) +
    (grade.chain || 0) +
    (grade.report_quality || 0);
  let disposition = 'SKIP';
  if (total >= 40) disposition = 'SUBMIT';
  else if (total >= 20) disposition = 'HOLD';
  return { total, disposition };
}

function findingCreate(args) {
  const {
    vuln_class,
    claim,
    location,
    cwe,
    severity,
    attack_vector,
    run,
    target,
    evidence,
    reasoning_trace_ref,
  } = args;

  if (!vuln_class) throw new Error('vuln_class is required (e.g. "sql-injection", "idor", "ssrf")');
  if (!claim) throw new Error('claim is required: one sentence describing the suspected weakness');
  if (severity && !VALID_SEVERITIES.includes(severity)) {
    throw new Error(`severity must be one of ${VALID_SEVERITIES.join(', ')}`);
  }
  if (scanForSecrets(args)) {
    throw new Error(
      'Refused: this finding payload looks like it contains a raw secret/token/key. ' +
        'Store a redacted reference or hash instead -- never the raw credential (PRD section 9/11).',
    );
  }

  const id = newId();
  const finding = {
    id,
    schema_version: 1,
    run: run || null,
    target: target || null,
    vuln_class,
    cwe: cwe || null,
    status: 'candidate',
    severity: severity || null,
    location: location || null,
    claim,
    attack_vector: attack_vector || null,
    reasoning_trace_ref: reasoning_trace_ref || null,
    evidence: Array.isArray(evidence) ? evidence : [],
    poc: null,
    patch: null,
    grade: null,
    disposition: null,
    rejected_reason: null,
    first_seen_run: run || null,
    last_seen_run: run || null,
    created_at: nowIso(),
    updated_at: nowIso(),
    history: [{ at: nowIso(), status: 'candidate', note: 'created' }],
  };

  appendEvent({ kind: 'create', at: nowIso(), finding });
  return { ok: true, id, status: 'candidate', finding };
}

function findingUpdate(args) {
  const { id, status, severity, evidence, poc, patch, grade, rejected_reason, note, run } = args;
  if (!id) throw new Error('id is required');
  if (scanForSecrets(args)) {
    throw new Error(
      'Refused: this update payload looks like it contains a raw secret/token/key. ' +
        'Store a redacted reference or hash instead (PRD section 9/11).',
    );
  }

  const findings = loadState();
  const existing = findings.get(id);
  if (!existing) throw new Error(`Unknown finding id: ${id}`);

  const changes = {};

  if (status && status !== existing.status) {
    const allowed = STATUS_TRANSITIONS[existing.status] || [];
    if (!allowed.includes(status)) {
      throw new Error(
        `Illegal transition ${existing.status} -> ${status}. ` +
          `Allowed from ${existing.status}: ${allowed.length ? allowed.join(', ') : '(terminal, none)'}.`,
      );
    }
    if (status === 'rejected' && !rejected_reason) {
      throw new Error(
        'Rejecting a finding requires rejected_reason citing the SPECIFIC roadblock ' +
          '(auth gate, sanitizer at sink, unreachable path, self-only harm, ...), not "seems safe" (PRD section 8).',
      );
    }
    if (status === 'confirmed') {
      const hasReach =
        args.reachability_note ||
        existing.reasoning_trace_ref ||
        (Array.isArray(existing.evidence) && existing.evidence.length > 0) ||
        (Array.isArray(evidence) && evidence.length > 0);
      if (!hasReach) {
        throw new Error(
          'Confirming a finding requires reachability/attack-simulation evidence: pass ' +
            'reachability_note or attach evidence first (PRD FR-6.1/6.3). No proof -> no confirm.',
        );
      }
    }
    changes.status = status;
    if (status === 'rejected') changes.rejected_reason = rejected_reason;
  }

  if (severity) {
    if (!VALID_SEVERITIES.includes(severity)) {
      throw new Error(`severity must be one of ${VALID_SEVERITIES.join(', ')}`);
    }
    changes.severity = severity;
  }
  if (Array.isArray(evidence)) {
    changes.evidence = [...(existing.evidence || []), ...evidence];
  }
  if (poc) changes.poc = poc;
  if (patch) changes.patch = patch;
  if (grade) {
    const disp = gradeToDisposition(grade);
    changes.grade = { ...grade, total: disp.total };
    changes.disposition = disp.disposition;
  }
  if (run) changes.last_seen_run = run;
  changes.updated_at = nowIso();

  const historyEntry = {
    at: nowIso(),
    status: changes.status || existing.status,
    note: note || (changes.status ? `transition to ${changes.status}` : 'update'),
  };

  appendEvent({ kind: 'update', at: nowIso(), id, changes, history_entry: historyEntry });

  const merged = { ...existing, ...changes, history: [...(existing.history || []), historyEntry] };
  return { ok: true, id, status: merged.status, disposition: merged.disposition || null, finding: merged };
}

function findingGet(args) {
  const { id } = args;
  if (!id) throw new Error('id is required');
  const finding = loadState().get(id);
  if (!finding) throw new Error(`Unknown finding id: ${id}`);
  return finding;
}

function findingList(args = {}) {
  const { status, severity, vuln_class, run } = args;
  let items = [...loadState().values()];
  if (status) items = items.filter((f) => f.status === status);
  if (severity) items = items.filter((f) => f.severity === severity);
  if (vuln_class) items = items.filter((f) => f.vuln_class === vuln_class);
  if (run) items = items.filter((f) => f.run === run || f.last_seen_run === run);

  const by = (key) =>
    items.reduce((acc, f) => {
      const k = f[key] || 'unknown';
      acc[k] = (acc[k] || 0) + 1;
      return acc;
    }, {});

  return {
    count: items.length,
    summary: { by_status: by('status'), by_severity: by('severity') },
    findings: items.map((f) => ({
      id: f.id,
      status: f.status,
      severity: f.severity,
      vuln_class: f.vuln_class,
      claim: f.claim,
      disposition: f.disposition,
      location: f.location,
    })),
  };
}

createServer({
  name: 'mantis-findings',
  version: '0.1.0',
  tools: [
    {
      name: 'finding_create',
      description:
        'Register a new `candidate` finding in the tool-owned findings spine. Detect/recon stages call this; do NOT self-censor false positives here (that is Validate\'s job). Returns the assigned finding id. Never pass raw secrets -- store redacted references.',
      inputSchema: {
        type: 'object',
        properties: {
          vuln_class: { type: 'string', description: 'Vulnerability class, e.g. "sql-injection", "idor", "ssrf", "rce", "secret-exposure".' },
          claim: { type: 'string', description: 'One sentence: the suspected weakness and why.' },
          location: {
            type: 'object',
            description: 'Where it lives.',
            properties: {
              file: { type: 'string' },
              lines: { type: 'string', description: 'e.g. "42" or "42-58".' },
              symbol: { type: 'string', description: 'Enclosing function/route/handler.' },
            },
          },
          cwe: { type: 'string', description: 'CWE id if known, e.g. "CWE-89".' },
          severity: { type: 'string', enum: VALID_SEVERITIES, description: 'Provisional severity; final severity = demonstrated outcome.' },
          attack_vector: { type: 'string', description: 'How an attacker would reach/trigger it.' },
          evidence: { type: 'array', items: { type: 'object' }, description: 'Bounded evidence refs (hashes, redacted samples, file:line refs). Never raw secrets/bodies.' },
          reasoning_trace_ref: { type: 'string', description: 'Reference to the reasoning trace for this candidate.' },
          run: { type: 'string', description: 'Run id, for cross-run dedup/first-last-seen.' },
          target: { type: 'string', description: 'Target id/name.' },
        },
        required: ['vuln_class', 'claim'],
      },
      handler: findingCreate,
    },
    {
      name: 'finding_update',
      description:
        'Advance a finding through its lifecycle (candidate -> confirmed|rejected -> exploited -> fixed -> verified) or attach evidence/poc/patch/grade. Confirming requires reachability/attack-sim evidence; rejecting requires a cited roadblock. Enforces legal transitions and grading (SUBMIT/HOLD/SKIP).',
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'Finding id from finding_create.' },
          status: { type: 'string', enum: VALID_STATUSES, description: 'Target lifecycle status.' },
          severity: { type: 'string', enum: VALID_SEVERITIES },
          reachability_note: { type: 'string', description: 'Required to move to `confirmed` if no evidence/trace is attached yet: how attacker input provably reaches the sink.' },
          rejected_reason: { type: 'string', description: 'Required to move to `rejected`: the SPECIFIC roadblock that kills exploitability.' },
          evidence: { type: 'array', items: { type: 'object' }, description: 'Additional bounded evidence refs to append.' },
          poc: { type: 'object', description: 'PoC descriptor {kind, ref, reproduced}. Gated exploit stage only.' },
          patch: { type: 'object', description: 'Patch descriptor {diff_ref, regression_checked, pr_url}.' },
          grade: {
            type: 'object',
            description: '5-axis grade; total + disposition (SUBMIT>=40 / HOLD 20-39 / SKIP<20) are computed for you.',
            properties: {
              impact: { type: 'number', description: '0-30' },
              proof: { type: 'number', description: '0-25' },
              severity_accuracy: { type: 'number', description: '0-15' },
              chain: { type: 'number', description: '0-15' },
              report_quality: { type: 'number', description: '0-15' },
            },
          },
          note: { type: 'string', description: 'Free-text history note for this transition.' },
          run: { type: 'string', description: 'Run id (updates last_seen_run).' },
        },
        required: ['id'],
      },
      handler: findingUpdate,
    },
    {
      name: 'finding_get',
      description: 'Fetch the full current state + history of one finding by id.',
      inputSchema: {
        type: 'object',
        properties: { id: { type: 'string' } },
        required: ['id'],
      },
      handler: findingGet,
    },
    {
      name: 'finding_list',
      description: 'List/triage findings with optional filters, plus a by-status/by-severity summary. Use this to see the current run\'s queue before reporting.',
      inputSchema: {
        type: 'object',
        properties: {
          status: { type: 'string', enum: VALID_STATUSES },
          severity: { type: 'string', enum: VALID_SEVERITIES },
          vuln_class: { type: 'string' },
          run: { type: 'string' },
        },
      },
      handler: findingList,
    },
  ],
});
