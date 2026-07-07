"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { redactSecrets, containsSecret } = require("./secret_patterns.js");

test("redacts an AWS access key id", () => {
  assert.equal(
    redactSecrets("key=AKIAABCDEFGHIJKLMNOP end"),
    "key=[REDACTED_AWS_KEY] end",
  );
});

test("redacts a GitHub fine-grained PAT", () => {
  const raw = "github_pat_" + "a".repeat(30);
  assert.ok(!redactSecrets(raw).includes(raw));
  assert.match(redactSecrets(raw), /\[REDACTED_GH_TOKEN\]/);
});

test("redacts a Stripe live secret key", () => {
  assert.match(
    redactSecrets("Authorization uses sk_live_abcdefghijklmnop1234"),
    /\[REDACTED_STRIPE_KEY\]/,
  );
});

test("redacts a Google API key (39 chars total)", () => {
  const key = "AIza" + "A".repeat(35);
  assert.match(redactSecrets(`key=${key}`), /\[REDACTED_GOOGLE_API_KEY\]/);
});

test("redacts an npm publish token", () => {
  const token = "npm_" + "a".repeat(36);
  assert.match(redactSecrets(token), /\[REDACTED_NPM_TOKEN\]/);
});

test("redacts userinfo embedded in a URL", () => {
  assert.equal(
    redactSecrets("http://user:passw0rd@host.example/path"),
    "http://[REDACTED_USERINFO]@host.example/path",
  );
});

test("redacts a generic named secret query param", () => {
  assert.equal(
    redactSecrets("GET /callback?token=abcdef123456&x=1"),
    "GET /callback?token=[REDACTED]&x=1",
  );
});

test("redacts a PEM private key block", () => {
  const pem =
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAKC\n-----END RSA PRIVATE KEY-----";
  assert.equal(redactSecrets(pem), "[REDACTED_PRIVATE_KEY]");
});

test("leaves ordinary text untouched", () => {
  const text = "This is a normal log line with no secrets in it.";
  assert.equal(redactSecrets(text), text);
});

test("containsSecret is stateless across repeated calls (no regex lastIndex leakage)", () => {
  const withSecret = "AKIAABCDEFGHIJKLMNOP";
  assert.equal(containsSecret(withSecret), true);
  assert.equal(containsSecret(withSecret), true);
  assert.equal(containsSecret(withSecret), true);
});

test("containsSecret returns false for clean text", () => {
  assert.equal(containsSecret("nothing secret here"), false);
});

test("containsSecret checks object payloads via JSON stringification", () => {
  assert.equal(containsSecret({ note: "token=abcdef123456" }), true);
  assert.equal(containsSecret({ note: "all good" }), false);
});
