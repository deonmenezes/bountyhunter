"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function ruleById(id) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `rule ${id} not found`);
  return rule;
}

function fires(rule, text) {
  // Rules carry the `g` flag and are shared/reused across scans, so reset
  // lastIndex the same way the real scanner must to avoid stateful reuse bugs.
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(text);
}

test("js.ssrf.fetch_source fires on fetch() with a request source", () => {
  const rule = ruleById("js.ssrf.fetch_source");
  assert.equal(fires(rule, "await fetch(req.query.url);"), true);
});

test("js.ssrf.fetch_source does not fire on a static fetch", () => {
  const rule = ruleById("js.ssrf.fetch_source");
  assert.equal(
    fires(rule, 'await fetch("https://api.example.com/health");'),
    false,
  );
});

test("js.ssrf.axios_source fires on axios.get with a request source", () => {
  const rule = ruleById("js.ssrf.axios_source");
  assert.equal(fires(rule, "await axios.get(req.body.callbackUrl);"), true);
});

test("js.ssrf.axios_source does not fire on a static axios call", () => {
  const rule = ruleById("js.ssrf.axios_source");
  assert.equal(
    fires(rule, 'await axios.get("https://internal.example.com/status");'),
    false,
  );
});

test("js.ssrf.http_request_source fires on http.get with a request source", () => {
  const rule = ruleById("js.ssrf.http_request_source");
  assert.equal(fires(rule, "http.get(req.query.target, cb);"), true);
});

test("py.ssrf.requests_source fires on requests.get with a Flask request source", () => {
  const rule = ruleById("py.ssrf.requests_source");
  assert.equal(fires(rule, 'resp = requests.get(request.args["url"])'), true);
});

test("py.ssrf.requests_source does not fire on a static requests call", () => {
  const rule = ruleById("py.ssrf.requests_source");
  assert.equal(
    fires(rule, 'resp = requests.get("https://api.example.com/ping")'),
    false,
  );
});

test("py.ssrf.urlopen_source fires on urlopen with a request source", () => {
  const rule = ruleById("py.ssrf.urlopen_source");
  assert.equal(fires(rule, "resp = urlopen(request.args.get('url'))"), true);
});

test("go.ssrf.http_get_source fires on http.Get with an http request source", () => {
  const rule = ruleById("go.ssrf.http_get_source");
  assert.equal(
    fires(rule, 'resp, err := http.Get(r.FormValue("target"))'),
    true,
  );
});

test("go.ssrf.http_get_source does not fire on a static http.Get", () => {
  const rule = ruleById("go.ssrf.http_get_source");
  assert.equal(
    fires(rule, 'resp, err := http.Get("https://api.example.com/ping")'),
    false,
  );
});

test("java.ssrf.url_connection_param fires on new URL() with request.getParameter", () => {
  const rule = ruleById("java.ssrf.url_connection_param");
  assert.equal(
    fires(rule, 'URL u = new URL(request.getParameter("target"));'),
    true,
  );
});

test("java.ssrf.url_connection_param does not fire on a static URL", () => {
  const rule = ruleById("java.ssrf.url_connection_param");
  assert.equal(
    fires(rule, 'URL u = new URL("https://api.example.com/ping");'),
    false,
  );
});

test("every CWE-918 sink rule is tagged and unique", () => {
  const ssrfRules = RULES.filter((r) => r.cwe === "CWE-918");
  assert.equal(ssrfRules.length, 7);
  const ids = ssrfRules.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate rule ids");
  for (const rule of ssrfRules) {
    assert.equal(rule.kind, "sink");
    assert.ok(rule.pattern.flags.includes("g"), `${rule.id} must be global`);
  }
});

test("all rule ids across the table are unique", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate rule ids in RULES");
});
