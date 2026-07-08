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

test("js.path.join_source fires on path.join with a request source", () => {
  const rule = ruleById("js.path.join_source");
  assert.equal(
    fires(rule, "const p = path.join(baseDir, req.query.file);"),
    true,
  );
});

test("js.path.join_source does not fire on a static join", () => {
  const rule = ruleById("js.path.join_source");
  assert.equal(fires(rule, 'const p = path.join(__dirname, "assets");'), false);
});

test("js.fs.dynamic_concat fires on fs read with string concatenation", () => {
  const rule = ruleById("js.fs.dynamic_concat");
  assert.equal(
    fires(rule, 'fs.readFileSync("/data/" + name + ".json");'),
    true,
  );
});

test("js.fs.dynamic_concat does not fire on a static fs read", () => {
  const rule = ruleById("js.fs.dynamic_concat");
  assert.equal(fires(rule, 'fs.readFileSync("/data/config.json");'), false);
});

test("py.path.join_source fires on os.path.join with a Flask request source", () => {
  const rule = ruleById("py.path.join_source");
  assert.equal(
    fires(rule, 'path = os.path.join(UPLOAD_DIR, request.args["name"])'),
    true,
  );
});

test("py.path.join_source does not fire on a static join", () => {
  const rule = ruleById("py.path.join_source");
  assert.equal(
    fires(rule, 'path = os.path.join(UPLOAD_DIR, "default.txt")'),
    false,
  );
});

test("py.open.fstring fires on open() called with an f-string path", () => {
  const rule = ruleById("py.open.fstring");
  assert.equal(fires(rule, 'with open(f"/data/{filename}") as fh:'), true);
});

test("py.open.fstring does not fire on open() with a plain string", () => {
  const rule = ruleById("py.open.fstring");
  assert.equal(fires(rule, 'with open("/data/config.json") as fh:'), false);
});

test("py.flask.send_file_source fires on send_file with a request source", () => {
  const rule = ruleById("py.flask.send_file_source");
  assert.equal(fires(rule, 'return send_file(request.args.get("path"))'), true);
});

test("go.path.join_source fires on filepath.Join with an http request source", () => {
  const rule = ruleById("go.path.join_source");
  assert.equal(
    fires(rule, 'p := filepath.Join(baseDir, r.FormValue("name"))'),
    true,
  );
});

test("go.os.open_sprintf fires on os.Open with fmt.Sprintf", () => {
  const rule = ruleById("go.os.open_sprintf");
  assert.equal(
    fires(rule, 'f, err := os.Open(fmt.Sprintf("/data/%s", name))'),
    true,
  );
});

test("go.os.open_sprintf does not fire on os.Open with a static path", () => {
  const rule = ruleById("go.os.open_sprintf");
  assert.equal(fires(rule, 'f, err := os.Open("/data/config.json")'), false);
});

test("java.file.request_param fires on new File() with request.getParameter", () => {
  const rule = ruleById("java.file.request_param");
  assert.equal(
    fires(rule, 'File f = new File(baseDir, request.getParameter("name"));'),
    true,
  );
});

test("java.paths.get_request_param fires on Paths.get() with request.getParameter", () => {
  const rule = ruleById("java.paths.get_request_param");
  assert.equal(
    fires(rule, 'Path p = Paths.get(baseDir, request.getParameter("name"));'),
    true,
  );
});

test("every CWE-22 sink rule is tagged and unique", () => {
  const pathTraversalRules = RULES.filter((r) => r.cwe === "CWE-22");
  assert.equal(pathTraversalRules.length, 9);
  const ids = pathTraversalRules.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate rule ids");
  for (const rule of pathTraversalRules) {
    assert.equal(rule.kind, "sink");
    assert.ok(rule.pattern.flags.includes("g"), `${rule.id} must be global`);
  }
});

test("all rule ids across the table are unique", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate rule ids in RULES");
});
