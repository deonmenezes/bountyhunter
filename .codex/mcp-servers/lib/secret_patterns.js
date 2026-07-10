"use strict";

/**
 * Canonical secret-shaped patterns shared by every Mantis MCP server that
 * detects or redacts raw credentials (PRD section 9/11 DLP backstop).
 *
 * http-audit and findings used to keep independently-maintained copies of
 * this list. They drifted: findings' create/update guard was missing the
 * userinfo@ and generic `token=`/`password=`/... key-value shapes that
 * http-audit already redacted, so a finding payload could carry a raw
 * secret past the findings-spine gate even though http-audit would have
 * caught the same string. Centralizing here means both gates see the same
 * coverage and can't silently fall out of sync again.
 */
const SECRET_REDACT_PATTERNS = [
  [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_KEY]"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, "[REDACTED_GH_TOKEN]"],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "[REDACTED_SLACK_TOKEN]"],
  [/\bsk_live_[A-Za-z0-9]{16,}\b/g, "[REDACTED_STRIPE_KEY]"],
  [/\bAIza[A-Za-z0-9_-]{35}\b/g, "[REDACTED_GOOGLE_API_KEY]"],
  [
    /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    "[REDACTED_JWT]",
  ],
  [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    "[REDACTED_PRIVATE_KEY]",
  ],
  [/\b[A-Za-z0-9._%+-]+:[^@\s/]{6,}@/g, "[REDACTED_USERINFO]@"], // user:pass@ in URLs
  [
    /\b(token|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|auth|session[_-]?id|sig|signature)=([^&\s]+)/gi,
    (_match, name) => `${name}=[REDACTED]`,
  ],
];

// Detection-only companion for the private-key shape: a bare BEGIN marker
// with no matching END is still a leaked key (e.g. a truncated preview), so
// boolean detection must not require the END anchor the redaction pattern
// needs to know how much text to replace.
const PRIVATE_KEY_BEGIN_ONLY = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;

function redactAll(text) {
  let out = String(text);
  for (const [re, repl] of SECRET_REDACT_PATTERNS) out = out.replace(re, repl);
  return out;
}

function containsSecretShape(value) {
  const hay = typeof value === "string" ? value : JSON.stringify(value ?? "");
  if (PRIVATE_KEY_BEGIN_ONLY.test(hay)) return true;
  return SECRET_REDACT_PATTERNS.some(([re]) => {
    re.lastIndex = 0; // guard against stateful /g regex reuse
    return re.test(hay);
  });
}

module.exports = { SECRET_REDACT_PATTERNS, redactAll, containsSecretShape };
