"use strict";

/**
 * Canonical secret-shape patterns, shared by every server that must keep a
 * raw credential from surviving into a finding or an evidence pack (PRD
 * section 9/11 secrets/DLP). Single source of truth so the http-audit
 * redactor and the findings-spine DLP guard can't silently drift out of sync
 * -- they had: http-audit already redacted JWTs, `user:pass@` URL userinfo,
 * and generically-named `token=`/`password=`-style params that the
 * findings/server.js `scanForSecrets` guard did not know about, so a finding
 * payload carrying one of those would sail past the "never raw secrets"
 * refusal even though the evidence-pack redactor would have caught it.
 *
 * Every `source` is written without the "g" flag. Callers needing a global
 * match (redaction) build their own fresh RegExp per call via
 * `globalPatterns()` so a reused global RegExp's `lastIndex` can never leak a
 * false negative into `.test()`-based detection (the classic global-regex
 * `.test()` statefulness bug).
 */
const SECRET_PATTERNS = [
  {
    name: "aws_access_key_id",
    source: "\\bAKIA[0-9A-Z]{16}\\b",
    replacement: "[REDACTED_AWS_KEY]",
  },
  {
    name: "github_token",
    source: "\\bgh[pousr]_[A-Za-z0-9]{20,}\\b",
    replacement: "[REDACTED_GH_TOKEN]",
  },
  {
    name: "slack_token",
    source: "\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b",
    replacement: "[REDACTED_SLACK_TOKEN]",
  },
  {
    name: "pem_private_key",
    source:
      "-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    replacement: "[REDACTED_PRIVATE_KEY]",
  },
  {
    name: "jwt",
    source:
      "\\bey[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b",
    replacement: "[REDACTED_JWT]",
  },
  {
    name: "google_api_key",
    source: "\\bAIza[0-9A-Za-z_-]{35}\\b",
    replacement: "[REDACTED_GOOGLE_API_KEY]",
  },
  {
    name: "stripe_live_key",
    source: "\\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\\b",
    replacement: "[REDACTED_STRIPE_KEY]",
  },
  {
    name: "npm_token",
    source: "\\bnpm_[A-Za-z0-9]{36}\\b",
    replacement: "[REDACTED_NPM_TOKEN]",
  },
  {
    name: "sendgrid_key",
    source: "\\bSG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}\\b",
    replacement: "[REDACTED_SENDGRID_KEY]",
  },
  {
    name: "url_userinfo",
    source: "\\b[A-Za-z0-9._%+-]+:[^@\\s/]{6,}@",
    replacement: "[REDACTED_USERINFO]@",
  },
  {
    name: "named_secret_param",
    source:
      "\\b(token|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|auth|session[_-]?id|sig|signature)=([^&\\s]+)",
    flags: "i",
    replacement: (_match, paramName) => `${paramName}=[REDACTED]`,
  },
];

// Fresh, non-global RegExp per pattern -- safe to `.test()` repeatedly since
// there is no "g"/"y" flag `lastIndex` to carry state between calls.
function detectPatterns() {
  return SECRET_PATTERNS.map((p) => new RegExp(p.source, p.flags || ""));
}

// Fresh, global RegExp per pattern -- for `.replace()`-based redaction of
// every occurrence, not just the first.
function globalPatterns() {
  return SECRET_PATTERNS.map((p) => new RegExp(p.source, `g${p.flags || ""}`));
}

function containsSecret(value) {
  const hay = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return detectPatterns().some((re) => re.test(hay));
}

module.exports = {
  SECRET_PATTERNS,
  detectPatterns,
  globalPatterns,
  containsSecret,
};
