"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  analyzeResponseSecurity,
  checkMissingHeaders,
  checkCookieFlags,
  checkCors,
} = require("./security_checks.js");

function headers(pairs) {
  return pairs.map(([name, value]) => ({ name, value }));
}

test("checkMissingHeaders flags HSTS/XCTO/CSP/frame-protection when all absent", () => {
  const findings = checkMissingHeaders(
    headers([["content-type", "text/html"]]),
  );
  const ids = findings.map((f) => f.id);
  assert.ok(ids.includes("http.missing_hsts"));
  assert.ok(ids.includes("http.missing_xcto"));
  assert.ok(ids.includes("http.missing_csp"));
  assert.ok(ids.includes("http.missing_frame_protection"));
});

test("checkMissingHeaders does not flag headers that are present", () => {
  const findings = checkMissingHeaders(
    headers([
      ["Strict-Transport-Security", "max-age=63072000"],
      ["X-Content-Type-Options", "nosniff"],
      ["Content-Security-Policy", "default-src 'self'"],
      ["X-Frame-Options", "DENY"],
    ]),
  );
  assert.deepEqual(findings, []);
});

test("checkMissingHeaders accepts CSP frame-ancestors as frame protection", () => {
  const findings = checkMissingHeaders(
    headers([["Content-Security-Policy", "frame-ancestors 'self'"]]),
  );
  const ids = findings.map((f) => f.id);
  assert.ok(!ids.includes("http.missing_frame_protection"));
  // CSP is present, so it should not also be reported missing.
  assert.ok(!ids.includes("http.missing_csp"));
});

test("checkCors flags wildcard origin with credentials", () => {
  const finding = checkCors(
    null,
    headers([
      ["Access-Control-Allow-Origin", "*"],
      ["Access-Control-Allow-Credentials", "true"],
    ]),
  );
  assert.equal(finding.id, "http.cors_wildcard_with_credentials");
  assert.equal(finding.cwe, "CWE-942");
});

test("checkCors flags reflected request Origin with credentials", () => {
  const finding = checkCors(
    headers([["Origin", "https://evil.example"]]),
    headers([
      ["Access-Control-Allow-Origin", "https://evil.example"],
      ["Access-Control-Allow-Credentials", "true"],
    ]),
  );
  assert.equal(finding.id, "http.cors_reflected_origin_with_credentials");
  assert.match(finding.detail, /https:\/\/evil\.example/);
});

test("checkCors does not flag a fixed allow-list origin without credentials", () => {
  const finding = checkCors(
    headers([["Origin", "https://evil.example"]]),
    headers([["Access-Control-Allow-Origin", "https://trusted.example"]]),
  );
  assert.equal(finding, null);
});

test("checkCors does not flag wildcard origin when credentials are absent", () => {
  const finding = checkCors(
    null,
    headers([["Access-Control-Allow-Origin", "*"]]),
  );
  assert.equal(finding, null);
});

test("checkCookieFlags flags a cookie missing Secure/HttpOnly/SameSite", () => {
  const findings = checkCookieFlags(
    headers([["Set-Cookie", "sessionid=s3cr3t-value-should-not-appear"]]),
  );
  const ids = findings.map((f) => f.id);
  assert.ok(ids.includes("http.cookie_missing_secure"));
  assert.ok(ids.includes("http.cookie_missing_httponly"));
  assert.ok(ids.includes("http.cookie_missing_samesite"));
  // The raw cookie value must never appear in a finding detail (DLP).
  for (const f of findings) {
    assert.ok(!f.detail.includes("s3cr3t-value-should-not-appear"));
  }
  assert.ok(findings.every((f) => f.detail.includes("sessionid")));
});

test("checkCookieFlags does not flag a fully-hardened cookie", () => {
  const findings = checkCookieFlags(
    headers([
      [
        "Set-Cookie",
        "sessionid=abc; Secure; HttpOnly; SameSite=Strict; Path=/",
      ],
    ]),
  );
  assert.deepEqual(findings, []);
});

test("checkCookieFlags flags SameSite=None as an improper attribute", () => {
  const findings = checkCookieFlags(
    headers([["Set-Cookie", "sessionid=abc; Secure; HttpOnly; SameSite=None"]]),
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "http.cookie_missing_samesite");
});

test("checkCookieFlags ignores non-Set-Cookie headers", () => {
  const findings = checkCookieFlags(headers([["Content-Type", "text/html"]]));
  assert.deepEqual(findings, []);
});

test("analyzeResponseSecurity combines all response-side checks", () => {
  const findings = analyzeResponseSecurity(
    headers([["Origin", "https://evil.example"]]),
    headers([
      ["Access-Control-Allow-Origin", "https://evil.example"],
      ["Access-Control-Allow-Credentials", "true"],
      ["Set-Cookie", "sessionid=abc"],
    ]),
  );
  const ids = findings.map((f) => f.id);
  assert.ok(ids.includes("http.cors_reflected_origin_with_credentials"));
  assert.ok(ids.includes("http.cookie_missing_secure"));
  assert.ok(ids.includes("http.missing_hsts"));
});
