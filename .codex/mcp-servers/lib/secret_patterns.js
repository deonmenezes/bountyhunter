"use strict";

/**
 * Shared secret-shape catalog for the Mantis DLP backstops (PRD section 9/11:
 * "never raw secrets/tokens/cookies/full bodies"). Two independent call sites
 * need this list -- `http-audit` (redact before returning an evidence pack)
 * and `findings` (refuse to persist a finding that carries a raw secret) --
 * and letting them keep separate copies had already let them drift out of
 * sync (findings' guard was missing patterns http-audit had, e.g. generic
 * `token=`/`password=` params and `user:pass@` URLs). One list, one place to
 * extend.
 *
 * Each entry is `[source, flags, replacement]`. `flags` never includes "g" --
 * callers derive a fresh RegExp with whatever flags they need (global for
 * `.replace`, non-global for a stateless `.test`) so a shared global regex
 * can't leak `lastIndex` state between callers.
 */
const SECRET_SHAPES = [
  // AWS access key id.
  ["\\bAKIA[0-9A-Z]{16}\\b", "", "[REDACTED_AWS_KEY]"],
  // AWS secret access key -- shape-only (base64-ish, 40 chars); paired with an
  // AKIA id in practice but the secret can appear alone in a leaked config.
  [
    "\\baws_secret_access_key\\s*[=:]\\s*[A-Za-z0-9/+]{40}\\b",
    "i",
    "aws_secret_access_key=[REDACTED]",
  ],
  // GitHub tokens (classic pat/oauth/user/server) and fine-grained PATs.
  ["\\bgh[pousr]_[A-Za-z0-9]{20,}\\b", "", "[REDACTED_GH_TOKEN]"],
  ["\\bgithub_pat_[A-Za-z0-9_]{20,}\\b", "", "[REDACTED_GH_TOKEN]"],
  // Slack tokens and incoming webhook URLs.
  ["\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b", "", "[REDACTED_SLACK_TOKEN]"],
  [
    "\\bhooks\\.slack\\.com/services/[A-Za-z0-9/]{20,}\\b",
    "",
    "hooks.slack.com/services/[REDACTED]",
  ],
  // Stripe secret/restricted keys (live and test).
  [
    "\\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\\b",
    "",
    "[REDACTED_STRIPE_KEY]",
  ],
  // Google API key.
  ["\\bAIza[0-9A-Za-z_-]{35}\\b", "", "[REDACTED_GOOGLE_API_KEY]"],
  // npm publish token.
  ["\\bnpm_[A-Za-z0-9]{36}\\b", "", "[REDACTED_NPM_TOKEN]"],
  // JWT-shaped bearer token (header.payload.signature).
  [
    "\\bey[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b",
    "",
    "[REDACTED_JWT]",
  ],
  // PEM private keys of any kind (RSA/EC/OPENSSH/PGP/generic).
  [
    "-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    "",
    "[REDACTED_PRIVATE_KEY]",
  ],
  // Credentials embedded in a URL: scheme://user:pass@host.
  ["\\b[A-Za-z0-9._%+-]+:[^@\\s/]{6,}@", "", "[REDACTED_USERINFO]@"],
  // Generically-named secret query/form params -- shape-based patterns above
  // can't catch these since the secret value itself has no distinctive shape.
  [
    "\\b(token|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|auth|session[_-]?id|sig|signature)=([^&\\s]+)",
    "i",
    (_match, name) => `${name}=[REDACTED]`,
  ],
];

function compile(shape, extraFlags) {
  const [source, flags, replacement] = shape;
  const combined = Array.from(new Set(`${flags}${extraFlags}`.split(""))).join(
    "",
  );
  return [new RegExp(source, combined), replacement];
}

/** Redacts every recognized secret shape in `text`, replacing in place. */
function redactSecrets(text) {
  let out = String(text);
  for (const shape of SECRET_SHAPES) {
    const [re, replacement] = compile(shape, "g");
    out = out.replace(re, replacement);
  }
  return out;
}

/** Stateless check: does `value` contain anything shaped like a raw secret? */
function containsSecret(value) {
  const hay = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return SECRET_SHAPES.some(([source, flags]) => {
    const [re] = compile([source, flags, null], "");
    return re.test(hay);
  });
}

module.exports = { redactSecrets, containsSecret };
