"use strict";

const { spawn } = require("node:child_process");

/**
 * Runs an external CLI tool and captures stdout/stderr/exit code.
 * Never throws on a missing binary or non-zero exit -- callers decide how to
 * interpret that, since e.g. semgrep/nuclei use non-zero exit codes to mean
 * "findings reported", not "tool failed".
 */
function runCommand(command, args, { cwd, input, timeoutMs = 120_000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd });
    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.on("error", (err) => {
      clearTimeout(timer);
      if (err.code === "ENOENT") {
        resolve({
          notFound: true,
          command,
          stdout: "",
          stderr: "",
          code: null,
        });
      } else {
        resolve({
          notFound: false,
          command,
          stdout: "",
          stderr: String(err),
          code: null,
        });
      }
    });

    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ notFound: false, command, stdout, stderr, code, timedOut });
    });

    if (input !== undefined) {
      child.stdin.write(input);
    }
    child.stdin.end();
  });
}

function notFoundMessage(toolName, installHint) {
  return `${toolName} is not installed or not on PATH in this environment. Install it (${installHint}) to enable this tool; until then this server reports rather than fabricates results.`;
}

module.exports = { runCommand, notFoundMessage };
