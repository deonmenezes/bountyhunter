"use strict";

/**
 * Heuristic attacker-controlled-source / dangerous-sink tagger.
 *
 * This is intentionally NOT a dataflow/taint engine -- it is a fast,
 * dependency-free proxy that surfaces candidate source and sink lines for a
 * human or the Validate-stage agent to actually trace and connect (FR-3.1/
 * FR-3.2's recall goal). It never claims reachability by itself; pair it
 * with smt_check_reachability once a concrete path condition is formed.
 */
const RULES = [
  // JavaScript / TypeScript
  {
    lang: "js",
    kind: "source",
    id: "js.http.query",
    pattern: /\breq\.(query|body|params|headers|cookies)\b/g,
  },
  {
    lang: "js",
    kind: "source",
    id: "js.process.argv",
    pattern: /\bprocess\.argv\b/g,
  },
  {
    lang: "js",
    kind: "source",
    id: "js.browser.location",
    pattern:
      /\b(location|window\.location|document\.location)\.(hash|search|href)\b/g,
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.eval",
    pattern: /\beval\s*\(/g,
    cwe: "CWE-95",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.new_function",
    pattern: /\bnew\s+Function\s*\(/g,
    cwe: "CWE-95",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.child_process.exec",
    pattern: /\b(child_process\.)?(exec|execSync)\s*\(/g,
    cwe: "CWE-78",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.dom.innerhtml",
    pattern: /\b(innerHTML|outerHTML)\s*=/g,
    cwe: "CWE-79",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.react.dangerously_set_inner_html",
    pattern: /dangerouslySetInnerHTML/g,
    cwe: "CWE-79",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.document.write",
    pattern: /\bdocument\.write\s*\(/g,
    cwe: "CWE-79",
  },
  {
    lang: "js",
    kind: "sink",
    id: "js.deserialize",
    pattern: /\b(node-serialize|serialize\.unserialize)\s*\(/g,
    cwe: "CWE-502",
  },

  // Python
  {
    lang: "py",
    kind: "source",
    id: "py.flask.request",
    pattern: /\brequest\.(args|form|values|cookies|headers|json)\b/g,
  },
  {
    lang: "py",
    kind: "source",
    id: "py.django.request",
    pattern: /\brequest\.(GET|POST)\b/g,
  },
  { lang: "py", kind: "source", id: "py.sys.argv", pattern: /\bsys\.argv\b/g },
  {
    lang: "py",
    kind: "sink",
    id: "py.eval_exec",
    pattern: /\b(eval|exec)\s*\(/g,
    cwe: "CWE-95",
  },
  {
    lang: "py",
    kind: "sink",
    id: "py.os.system",
    pattern: /\bos\.system\s*\(/g,
    cwe: "CWE-78",
  },
  {
    lang: "py",
    kind: "sink",
    id: "py.subprocess.shell_true",
    pattern: /subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True/g,
    cwe: "CWE-78",
  },
  {
    lang: "py",
    kind: "sink",
    id: "py.pickle.loads",
    pattern: /\bpickle\.loads?\s*\(/g,
    cwe: "CWE-502",
  },
  {
    lang: "py",
    kind: "sink",
    id: "py.yaml.load_unsafe",
    pattern: /\byaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)/g,
    cwe: "CWE-502",
  },

  // Go
  {
    lang: "go",
    kind: "source",
    id: "go.http.request",
    pattern: /\br\.(URL\.Query\(\)|FormValue|PostFormValue)\b/g,
  },
  { lang: "go", kind: "source", id: "go.os.args", pattern: /\bos\.Args\b/g },
  {
    lang: "go",
    kind: "sink",
    id: "go.exec.command",
    pattern: /\bexec\.Command\s*\(/g,
    cwe: "CWE-78",
  },
  {
    lang: "go",
    kind: "sink",
    id: "go.template.html",
    pattern: /\btemplate\.HTML\s*\(/g,
    cwe: "CWE-79",
  },

  // Java
  {
    lang: "java",
    kind: "source",
    id: "java.servlet.request",
    pattern: /\brequest\.get(Parameter|Header|QueryString)\s*\(/g,
  },
  {
    lang: "java",
    kind: "sink",
    id: "java.runtime.exec",
    pattern: /\bRuntime\.getRuntime\(\)\.exec\s*\(/g,
    cwe: "CWE-78",
  },
  {
    lang: "java",
    kind: "sink",
    id: "java.processbuilder",
    pattern: /\bnew\s+ProcessBuilder\s*\(/g,
    cwe: "CWE-78",
  },
  {
    lang: "java",
    kind: "sink",
    id: "java.objectinputstream",
    pattern: /\bnew\s+ObjectInputStream\s*\(/g,
    cwe: "CWE-502",
  },
  {
    lang: "java",
    kind: "sink",
    id: "java.statement.execute",
    pattern: /\bstatement\.execute(Query|Update)?\s*\(/gi,
    cwe: "CWE-89",
  },
];

module.exports = { RULES };
