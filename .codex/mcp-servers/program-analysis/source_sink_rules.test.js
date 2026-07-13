"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { RULES } = require("./source_sink_rules.js");

function ruleById(id) {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `expected a rule with id ${id}`);
  return rule;
}

function matches(rule, snippet) {
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(snippet);
}

// CWE-22 (path traversal) coverage added this run -- one positive and one
// negative case per new sink so the pattern doesn't regress into either a
// dead rule or a blanket match on unrelated code.

test("js.fs.path_ops matches fs read/write/stream/unlink calls", () => {
  const rule = ruleById("js.fs.path_ops");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, "fs.readFile(userPath, cb)"));
  assert.ok(matches(rule, "fs.createReadStream(req.query.path)"));
  assert.ok(matches(rule, "fs.writeFileSync(target, data)"));
  assert.ok(!matches(rule, "fs.watch(dir, cb)"));
});

test("js.express.sendfile matches res.sendFile/download, not res.send", () => {
  const rule = ruleById("js.express.sendfile");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, "res.sendFile(path.join(base, req.params.name))"));
  assert.ok(matches(rule, "res.download(userPath)"));
  assert.ok(!matches(rule, "res.send('ok')"));
});

test("py.flask.send_file matches send_file/send_from_directory", () => {
  const rule = ruleById("py.flask.send_file");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, "return send_file(user_supplied_path)"));
  assert.ok(matches(rule, "send_from_directory(base_dir, filename)"));
  assert.ok(!matches(rule, "return jsonify(status='ok')"));
});

test("go.http.servefile matches http.ServeFile, not unrelated http calls", () => {
  const rule = ruleById("go.http.servefile");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, "http.ServeFile(w, r, filepath.Join(base, name))"));
  assert.ok(!matches(rule, "http.Get(url)"));
});

test("java.file_stream matches new FileInputStream/FileOutputStream", () => {
  const rule = ruleById("java.file_stream");
  assert.equal(rule.cwe, "CWE-22");
  assert.ok(matches(rule, "new FileInputStream(uploadDir + filename)"));
  assert.ok(matches(rule, "new FileOutputStream(target)"));
  assert.ok(!matches(rule, "new BufferedReader(reader)"));
});

// Spot-check a couple of pre-existing rules still work after the edit --
// regression guard against a stray typo breaking the shared RULES array.

test("existing js.eval and py.os.system rules are unaffected", () => {
  assert.ok(matches(ruleById("js.eval"), "eval(userInput)"));
  assert.ok(matches(ruleById("py.os.system"), "os.system(cmd)"));
});
