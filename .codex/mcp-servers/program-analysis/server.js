#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { createServer } = require("../lib/mcp_stdio.js");
const { runCommand, notFoundMessage } = require("../lib/run_tool.js");
const { RULES } = require("./source_sink_rules.js");

const EXCLUDED_DIRS = new Set([
  ".git",
  "node_modules",
  "target",
  "dist",
  "build",
  "vendor",
  ".venv",
  "__pycache__",
]);
const MAX_FILE_BYTES = 1_000_000;
const MAX_FILES = 5_000;

const EXTENSION_TO_LANG = {
  ".js": "js",
  ".jsx": "js",
  ".ts": "js",
  ".tsx": "js",
  ".mjs": "js",
  ".cjs": "js",
  ".py": "py",
  ".go": "go",
  ".java": "java",
};

function langForFile(file) {
  return EXTENSION_TO_LANG[path.extname(file).toLowerCase()] || null;
}

function walk(root) {
  const files = [];
  const stack = [root];
  while (stack.length && files.length < MAX_FILES) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (EXCLUDED_DIRS.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile()) {
        files.push(full);
      }
    }
  }
  return files;
}

async function astGrepScan({ path: targetPath, pattern, lang }) {
  if (!targetPath || !pattern || !lang)
    throw new Error("path, pattern, and lang are required");

  const result = await runCommand(
    "ast-grep",
    ["run", "--pattern", pattern, "--lang", lang, "--json=stream", targetPath],
    {
      timeoutMs: 120_000,
    },
  );
  if (result.notFound) {
    return {
      tool: "ast-grep",
      available: false,
      message: notFoundMessage(
        "ast-grep",
        "brew install ast-grep, or cargo install ast-grep",
      ),
    };
  }

  const matches = [];
  for (const line of result.stdout.split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      const items = Array.isArray(parsed) ? parsed : [parsed];
      for (const m of items) {
        matches.push({
          file: m.file,
          start_line: m.range && m.range.start && m.range.start.line + 1,
          end_line: m.range && m.range.end && m.range.end.line + 1,
          text: m.text,
        });
      }
    } catch {
      // ast-grep --json=stream emits one JSON array or object per line; skip lines that don't parse.
    }
  }

  return {
    tool: "ast-grep",
    available: true,
    match_count: matches.length,
    matches,
  };
}

async function sourceSinkScan({ path: targetPath, languages }) {
  if (!targetPath) throw new Error("path is required");

  const stat = fs.statSync(targetPath);
  const files = stat.isDirectory() ? walk(targetPath) : [targetPath];
  const allowedLangs = languages ? new Set(languages) : null;

  const findings = [];
  for (const file of files) {
    const fileLang = langForFile(file);
    if (!fileLang) continue;
    if (allowedLangs && !allowedLangs.has(fileLang)) continue;
    const activeRules = RULES.filter((r) => r.lang === fileLang);
    if (activeRules.length === 0) continue;

    let stat_;
    try {
      stat_ = fs.statSync(file);
    } catch {
      continue;
    }
    if (stat_.size > MAX_FILE_BYTES) continue;

    let content;
    try {
      content = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }

    const lines = content.split("\n");
    for (const rule of activeRules) {
      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(content)) !== null) {
        const upToMatch = content.slice(0, match.index);
        const lineNumber = upToMatch.split("\n").length;
        findings.push({
          rule_id: rule.id,
          kind: rule.kind,
          cwe: rule.cwe,
          file,
          line: lineNumber,
          snippet: (lines[lineNumber - 1] || "").trim().slice(0, 200),
        });
        if (rule.pattern.lastIndex === match.index) rule.pattern.lastIndex++; // avoid infinite loop on zero-width matches
      }
    }
  }

  return {
    tool: "source-sink-heuristic",
    available: true,
    note: "Heuristic regex proxy for FR-3.1/FR-3.2, not a dataflow/taint engine. Confirm any real source->sink connection by tracing the code before treating it as reachable.",
    files_scanned: files.length,
    candidate_count: findings.length,
    sources: findings.filter((f) => f.kind === "source"),
    sinks: findings.filter((f) => f.kind === "sink"),
  };
}

async function smtCheckReachability({ smt2_script: smt2Script }) {
  if (!smt2Script) throw new Error("smt2_script is required");

  const script = smt2Script.includes("(check-sat)")
    ? smt2Script
    : `${smt2Script}\n(check-sat)\n`;
  const result = await runCommand("z3", ["-in"], {
    input: script,
    timeoutMs: 30_000,
  });
  if (result.notFound) {
    return {
      tool: "z3",
      available: false,
      message: notFoundMessage("z3", "brew install z3, or apt-get install z3"),
    };
  }

  const output = result.stdout.trim();
  const firstLine = output.split("\n")[0];
  let verdict = "unknown";
  if (firstLine === "sat") verdict = "sat";
  else if (firstLine === "unsat") verdict = "unsat";

  return {
    tool: "z3",
    available: true,
    verdict,
    meaning:
      verdict === "unsat"
        ? "Path condition is UNSATISFIABLE -- this path is unreachable under the given constraints; reject the candidate."
        : verdict === "sat"
          ? "Path condition is SATISFIABLE -- an attacker-controlled assignment exists that reaches the sink; proceed to Validate."
          : "z3 could not decide (unknown/timeout); do not treat this as proof either way.",
    raw_output: output.slice(0, 2000),
    stderr: result.stderr.slice(0, 2000),
  };
}

createServer({
  name: "mantis-program-analysis",
  version: "0.1.0",
  tools: [
    {
      name: "ast_grep_scan",
      description:
        "Structural AST pattern search via ast-grep (tree-sitter backed). Use for precise call-graph/API-usage queries beyond plain regex.",
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "File or directory to search." },
          pattern: {
            type: "string",
            description: 'ast-grep pattern, e.g. "exec($CMD)".',
          },
          lang: {
            type: "string",
            description:
              "Language id, e.g. javascript, typescript, python, go, java, rust.",
          },
        },
        required: ["path", "pattern", "lang"],
      },
      handler: astGrepScan,
    },
    {
      name: "source_sink_scan",
      description:
        "Fast, dependency-free heuristic scan tagging attacker-controlled-input sources and dangerous sinks (Recon/Detect stages, FR-3.1/FR-3.2). NOT a taint engine -- surfaces candidates for the agent to trace and connect.",
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "File or directory to scan." },
          languages: {
            type: "array",
            items: { type: "string", enum: ["js", "py", "go", "java"] },
            description:
              "Restrict to these language rule sets. Defaults to all.",
          },
        },
        required: ["path"],
      },
      handler: sourceSinkScan,
    },
    {
      name: "smt_check_reachability",
      description:
        "SMT-backed reachability check (FR-3.3): decide satisfiability of a path condition over attacker-controlled values via z3. Construct the SMT-LIB2 script yourself from the traced source->sink path; this tool only solves it.",
      inputSchema: {
        type: "object",
        properties: {
          smt2_script: {
            type: "string",
            description:
              "SMT-LIB2 script (declare-const/assert statements). A trailing (check-sat) is added automatically if missing.",
          },
        },
        required: ["smt2_script"],
      },
      handler: smtCheckReachability,
    },
  ],
});
