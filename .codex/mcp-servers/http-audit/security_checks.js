"use strict";

/**
 * Pure security-misconfiguration / session-cookie heuristics for captured
 * HTTP traffic (PRD scan scope: "security misconfigurations", auth/session
 * flaws). Split out of server.js so it can be unit-tested without going
 * through the MCP stdio transport.
 *
 * Every check reads only header presence, attribute flags, or plain domain
 * values -- never a secret-bearing value -- so it stays consistent with the
 * "no raw secrets" DLP rule the rest of http-audit enforces.
 */

// Response headers whose *absence* is itself a misconfiguration candidate.
const MISSING_HEADER_CHECKS = [
  {
    header: "strict-transport-security",
    id: "http.missing_hsts",
    cwe: "CWE-319",
    detail: "Response has no Strict-Transport-Security header.",
  },
  {
    header: "x-content-type-options",
    id: "http.missing_xcto",
    cwe: "CWE-693",
    detail: "Response has no X-Content-Type-Options: nosniff header.",
  },
  {
    header: "content-security-policy",
    id: "http.missing_csp",
    cwe: "CWE-693",
    detail: "Response has no Content-Security-Policy header.",
  },
];

function findHeader(headers, name) {
  const hit = headers.find((h) => h.name.toLowerCase() === name);
  return hit ? hit.value : undefined;
}

// Clickjacking defense is satisfied by EITHER X-Frame-Options OR a CSP
// frame-ancestors directive -- only flag when both are absent.
function checkFrameProtection(headers) {
  if (findHeader(headers, "x-frame-options") !== undefined) return null;
  const csp = findHeader(headers, "content-security-policy");
  if (csp && /frame-ancestors/i.test(csp)) return null;
  return {
    id: "http.missing_frame_protection",
    cwe: "CWE-1021",
    detail:
      "Response has neither X-Frame-Options nor a CSP frame-ancestors directive (clickjacking).",
  };
}

function checkMissingHeaders(headers) {
  const findings = [];
  for (const check of MISSING_HEADER_CHECKS) {
    if (findHeader(headers, check.header) === undefined) {
      findings.push({ id: check.id, cwe: check.cwe, detail: check.detail });
    }
  }
  const frameFinding = checkFrameProtection(headers);
  if (frameFinding) findings.push(frameFinding);
  return findings;
}

// A wildcard or reflected-origin Access-Control-Allow-Origin combined with
// Access-Control-Allow-Credentials: true lets any site read credentialed
// responses (CWE-942). Origin/ACAO values are plain domains, never
// secret-bearing, so they're safe to quote in the finding detail.
function checkCors(requestHeaders, responseHeaders) {
  const acao = findHeader(responseHeaders, "access-control-allow-origin");
  if (!acao) return null;
  const acac = findHeader(responseHeaders, "access-control-allow-credentials");
  if (!acac || acac.trim().toLowerCase() !== "true") return null;

  if (acao.trim() === "*") {
    return {
      id: "http.cors_wildcard_with_credentials",
      cwe: "CWE-942",
      detail:
        "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.",
    };
  }

  const origin = requestHeaders
    ? findHeader(requestHeaders, "origin")
    : undefined;
  if (origin && origin.trim() === acao.trim()) {
    return {
      id: "http.cors_reflected_origin_with_credentials",
      cwe: "CWE-942",
      detail: `Access-Control-Allow-Origin reflects the request Origin (${acao.trim()}) alongside Access-Control-Allow-Credentials: true.`,
    };
  }
  return null;
}

// Session-cookie attribute checks (CWE-614/1004/1275). Only the cookie NAME
// (left of the first "=") and its attribute flags are inspected -- the
// cookie value itself is never read into a finding.
function checkCookieFlags(responseHeaders) {
  const findings = [];
  for (const { name, value } of responseHeaders) {
    if (name.toLowerCase() !== "set-cookie") continue;
    const cookieName = value.split("=")[0].trim() || "(unnamed)";
    const attrs = `${value.toLowerCase()};`;
    if (!/;\s*secure(\s*;|\s*$)/.test(attrs)) {
      findings.push({
        id: "http.cookie_missing_secure",
        cwe: "CWE-614",
        detail: `Set-Cookie "${cookieName}" is missing the Secure attribute.`,
      });
    }
    if (!attrs.includes("httponly")) {
      findings.push({
        id: "http.cookie_missing_httponly",
        cwe: "CWE-1004",
        detail: `Set-Cookie "${cookieName}" is missing the HttpOnly attribute.`,
      });
    }
    if (!/samesite=(strict|lax)/.test(attrs)) {
      findings.push({
        id: "http.cookie_missing_samesite",
        cwe: "CWE-1275",
        detail: `Set-Cookie "${cookieName}" has no SameSite=Strict|Lax attribute.`,
      });
    }
  }
  return findings;
}

// Runs every response-side check and returns the combined candidate list.
function analyzeResponseSecurity(requestHeaders, responseHeaders) {
  const findings = [
    ...checkMissingHeaders(responseHeaders),
    ...checkCookieFlags(responseHeaders),
  ];
  const corsFinding = checkCors(requestHeaders, responseHeaders);
  if (corsFinding) findings.push(corsFinding);
  return findings;
}

module.exports = {
  analyzeResponseSecurity,
  checkMissingHeaders,
  checkCookieFlags,
  checkCors,
  findHeader,
};
