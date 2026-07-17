"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { redactValue, auditExchange } = require("./server.js");

test("redactValue strips AWS access key ids", () => {
  const out = redactValue("key is AKIAABCDEFGHIJKLMNOP done");
  assert.equal(out, "key is [REDACTED_AWS_KEY] done");
});

test("redactValue strips classic and fine-grained GitHub tokens", () => {
  assert.equal(redactValue("ghp_" + "a".repeat(36)), "[REDACTED_GH_TOKEN]");
  assert.equal(
    redactValue("github_pat_" + "a".repeat(22) + "_" + "b".repeat(59)),
    "[REDACTED_GH_TOKEN]",
  );
});

test("redactValue strips Slack tokens and incoming webhook URLs", () => {
  assert.equal(
    redactValue("xoxb-123456789012-abcdefghij"),
    "[REDACTED_SLACK_TOKEN]",
  );
  const fakeWebhook =
    "https://hooks.slack.com/services/" +
    "T00000000" +
    "/" +
    "B00000000" +
    "/" +
    "z".repeat(24);
  assert.equal(redactValue(fakeWebhook), "[REDACTED_SLACK_WEBHOOK]");
});

test("redactValue strips Google API keys", () => {
  const key = "AIza" + "S".repeat(35);
  assert.equal(
    redactValue(`x-goog-key: ${key}`),
    `x-goog-key: [REDACTED_GOOGLE_API_KEY]`,
  );
});

test("redactValue strips Stripe live/test secret keys", () => {
  assert.equal(
    redactValue("sk_live_" + "a".repeat(24)),
    "[REDACTED_STRIPE_KEY]",
  );
  assert.equal(
    redactValue("rk_test_" + "a".repeat(24)),
    "[REDACTED_STRIPE_KEY]",
  );
});

test("redactValue strips npm and SendGrid tokens", () => {
  assert.equal(redactValue("npm_" + "a".repeat(36)), "[REDACTED_NPM_TOKEN]");
  assert.equal(
    redactValue("SG." + "a".repeat(22) + "." + "b".repeat(43)),
    "[REDACTED_SENDGRID_KEY]",
  );
});

test("redactValue strips JWTs and PEM private keys", () => {
  const jwt =
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ_abc123XYZ";
  assert.equal(redactValue(jwt), "[REDACTED_JWT]");

  const pem =
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJ...\n-----END RSA PRIVATE KEY-----";
  assert.equal(redactValue(pem), "[REDACTED_PRIVATE_KEY]");
});

test("redactValue strips userinfo credentials embedded in URLs", () => {
  assert.equal(
    redactValue("postgres://admin:hunter2secret@db.internal:5432/app"),
    "postgres://[REDACTED_USERINFO]@db.internal:5432/app",
  );
});

test("redactValue strips generically-named query/form secret params", () => {
  assert.equal(
    redactValue("/reset?token=abc123&next=/home"),
    "/reset?token=[REDACTED]&next=/home",
  );
  assert.equal(
    redactValue("password=hunter2&remember=1"),
    "password=[REDACTED]&remember=1",
  );
});

test("redactValue strips the same generically-named secrets in a JSON body", () => {
  const body = '{"username":"alice","password":"hunter2","ok":true}';
  assert.equal(
    redactValue(body),
    '{"username":"alice","password":"[REDACTED]","ok":true}',
  );

  const tokenBody = '{"access_token": "abc.def-123", "expires_in": 3600}';
  assert.equal(
    redactValue(tokenBody),
    '{"access_token":"[REDACTED]", "expires_in": 3600}',
  );
});

test("redactValue leaves ordinary, non-secret text untouched", () => {
  const text = "GET /api/widgets?page=2&sort=name HTTP/1.1";
  assert.equal(redactValue(text), text);
});

test("auditExchange redacts sensitive headers and JSON-body secrets end to end", () => {
  const request = [
    "POST /login HTTP/1.1",
    "Host: example.test",
    "Authorization: Bearer sometoken",
    "Cookie: session=abc123",
    "Content-Type: application/json",
    "",
    '{"username":"alice","password":"hunter2"}',
  ].join("\r\n");

  const pack = auditExchange({ request });
  assert.deepEqual(pack.request.redacted_headers, ["Authorization", "Cookie"]);
  assert.ok(
    pack.request.headers.every(
      (h) => h.name !== "Authorization" || h.value === "[REDACTED]",
    ),
  );
  assert.ok(!pack.request.body.preview.includes("hunter2"));
  assert.ok(pack.request.body.preview.includes('"password":"[REDACTED]"'));
  assert.match(pack.request.request_ref, /^req-[0-9a-f]{16}$/);
});
