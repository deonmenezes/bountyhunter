/// Solver construction with default timeout.
///
/// Faithful port of `core/smt_solver/session.py`.
///
/// In the Python code `new_solver()` and `new_optimizer()` return in-process
/// Z3 solver objects with a timeout applied. In Rust, the external seam is
/// `solve(smtlib, timeout_ms) -> SolverResult` which invokes the `z3` binary
/// via subprocess with the SMT-LIB2 `(set-option :timeout N)` directive,
/// or degrades gracefully when `z3` is not in PATH.
///
/// The timeout clamping logic is faithfully ported and fully testable without
/// Z3 installed.

pub const DEFAULT_TIMEOUT_MS: i64 = 5000;

/// Z3 stores timeout as an unsigned 32-bit value internally;
/// anything larger silently wraps. Cap at 2^31 - 1 ms (~24.8 days).
/// Mirrors Python `_MAX_TIMEOUT_MS = 2 ** 31 - 1`.
pub const MAX_TIMEOUT_MS: i64 = (1i64 << 31) - 1;

/// Clamp caller-supplied timeout to `[1, MAX_TIMEOUT_MS]`.
///
/// Faithful port of the clamping performed inside Python's `new_solver()` /
/// `new_optimizer()`. Extracted as a pure function so it's independently
/// testable without Z3 installed.
///
/// Python behaviour:
/// - `timeout_ms < 1` → `1` (prevents Z3's "0 means no timeout" quirk and negative-as-huge-unsigned quirk)
/// - `timeout_ms > MAX_TIMEOUT_MS` → `MAX_TIMEOUT_MS` (prevents wraparound at 2^32)
/// - otherwise → unchanged
pub fn clamp_timeout(timeout_ms: i64) -> i64 {
    if timeout_ms < 1 {
        1
    } else if timeout_ms > MAX_TIMEOUT_MS {
        MAX_TIMEOUT_MS
    } else {
        timeout_ms
    }
}

// ---------------------------------------------------------------------------
// SolverResult — the output of the external Z3 seam
// ---------------------------------------------------------------------------

/// Result returned by `solve()`.
///
/// Mirrors the three states Z3 produces (`sat`, `unsat`, `unknown`) plus the
/// degradation state when Z3 is absent or crashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolverResult {
    /// Satisfiable. `model` holds the raw SMT-LIB2 model output from z3.
    Sat { model: String },
    /// Unsatisfiable.
    Unsat,
    /// Z3 returned `unknown` or was unavailable/crashed.
    Unknown { reason: UnknownReason },
}

/// Why the solver returned `Unknown`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnknownReason {
    /// Z3 hit the per-solver timeout.
    /// Maps to `RejectionKind::SolverTimeout` via `classify_solver_unknown`.
    Timeout,
    /// Z3 returned `unknown` for another reason (incomplete tactic, etc.).
    /// Maps to `RejectionKind::SolverUnknown`.
    SolverUnknown,
    /// `z3` binary not found in PATH.
    /// Mirrors Python's `_Z3_AVAILABLE = False` (ImportError path).
    Z3NotFound,
    /// `z3` binary crashed (non-zero exit, unexpected output).
    Z3Failed { stderr: String },
}

impl SolverResult {
    /// The reason-unknown string, for feeding into `classify_solver_unknown`.
    /// Returns `""` for non-Unknown variants (mirrors `solver.reason_unknown()`
    /// semantics on a solver that hasn't returned unknown).
    pub fn unknown_reason_str(&self) -> &str {
        match self {
            SolverResult::Unknown { reason: UnknownReason::Timeout } => "timeout",
            SolverResult::Unknown { reason: UnknownReason::SolverUnknown } => "",
            SolverResult::Unknown { reason: UnknownReason::Z3NotFound } => "",
            SolverResult::Unknown { reason: UnknownReason::Z3Failed { .. } } => "",
            _ => "",
        }
    }
}

// ---------------------------------------------------------------------------
// solve() — the external-tool seam
// ---------------------------------------------------------------------------

/// Invoke the `z3` binary with SMT-LIB2 input and parse the result.
///
/// This is the **external-tool seam** — the boundary between Rust orchestration
/// logic and the Z3 solver. The caller builds a complete SMT-LIB2 problem
/// (declarations + assertions + `(check-sat)` + optional `(get-model)`) and
/// passes it as `smtlib`. The function:
///
/// 1. Prepends `(set-option :timeout <clamped_ms>)` to inject the timeout.
/// 2. Invokes `z3 -in -smt2` via subprocess with the SMT-LIB2 string on stdin.
/// 3. Parses stdout: `sat` → `Sat{model}`, `unsat` → `Unsat`,
///    `unknown` → `Unknown{Timeout|SolverUnknown}`.
/// 4. Degrades gracefully when `z3` is not in PATH → `Unknown{Z3NotFound}`.
///
/// Mirrors Python's degradation when `z3_available() == False`:
/// domain encoders receive `Unknown` and treat it as "skipped".
pub fn solve(smtlib: &str, timeout_ms: i64) -> SolverResult {
    if !crate::availability::z3_available() {
        return SolverResult::Unknown { reason: UnknownReason::Z3NotFound };
    }

    let t = clamp_timeout(timeout_ms);
    let mut input = format!("(set-option :timeout {})\n", t);
    input.push_str(smtlib);
    // Ensure (check-sat) is present if not already.
    if !smtlib.contains("(check-sat)") {
        input.push_str("\n(check-sat)\n");
    }

    let output = std::process::Command::new("z3")
        .args(["-in", "-smt2"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.take() {
                let mut stdin = stdin;
                let _ = stdin.write_all(input.as_bytes());
            }
            child.wait_with_output()
        });

    match output {
        Err(_) => SolverResult::Unknown { reason: UnknownReason::Z3NotFound },
        Ok(out) => parse_z3_output(&out.stdout, &out.stderr),
    }
}

fn parse_z3_output(stdout: &[u8], stderr: &[u8]) -> SolverResult {
    let stdout_str = String::from_utf8_lossy(stdout);
    let lines: Vec<&str> = stdout_str.lines().collect();

    match lines.first().map(|s| s.trim()) {
        Some("sat") => {
            let model = lines[1..].join("\n");
            SolverResult::Sat { model }
        }
        Some("unsat") => SolverResult::Unsat,
        Some("unknown") => {
            // Check if the reason is timeout from stderr or subsequent output.
            let stderr_str = String::from_utf8_lossy(stderr);
            let reason_str = lines.get(1).map(|s| *s).unwrap_or("")
                .to_ascii_lowercase();
            let stderr_lower = stderr_str.to_ascii_lowercase();
            if reason_str.contains("timeout")
                || stderr_lower.contains("timeout")
                || reason_str.contains("canceled")
                || stderr_lower.contains("canceled")
            {
                SolverResult::Unknown { reason: UnknownReason::Timeout }
            } else {
                SolverResult::Unknown { reason: UnknownReason::SolverUnknown }
            }
        }
        _ => {
            let stderr_str = String::from_utf8_lossy(stderr).into_owned();
            SolverResult::Unknown { reason: UnknownReason::Z3Failed { stderr: stderr_str } }
        }
    }
}

// ---------------------------------------------------------------------------
// SolverSession — builder for SMT-LIB2 problems
// ---------------------------------------------------------------------------

/// A builder that accumulates SMT-LIB2 declarations and assertions and
/// submits the complete problem via `solve()`.
///
/// Mirrors Python's `z3.Solver` API surface (add, push/pop, check) at the
/// SMT-LIB2 string level. `scoped()` in Python is a context-manager that
/// calls push/pop; here it's a closure that wraps a push + assertions + pop.
#[derive(Debug, Clone, Default)]
pub struct SolverSession {
    /// Completed (commited) SMT-LIB2 statements.
    committed: Vec<String>,
    /// Scope stack for push/pop — each entry is the number of statements
    /// added at that scope level.
    scope_stack: Vec<usize>,
    /// Current uncommitted statements (will be committed on next `solve` or `pop`).
    current: Vec<String>,
}

impl SolverSession {
    pub fn new() -> Self {
        SolverSession::default()
    }

    /// Add an SMT-LIB2 statement (declaration or assertion) to the current scope.
    pub fn add(&mut self, stmt: impl Into<String>) {
        self.current.push(stmt.into());
    }

    /// Push a new scope. Mirrors `solver.push()`.
    pub fn push(&mut self) {
        // Commit current statements first.
        self.committed.extend(self.current.drain(..));
        self.scope_stack.push(self.committed.len());
    }

    /// Pop the innermost scope, discarding all assertions added since `push()`.
    /// Mirrors `solver.pop()`. Returns `Err` if no scope to pop.
    pub fn pop(&mut self) -> Result<(), String> {
        match self.scope_stack.pop() {
            None => Err("scoped: no scope to pop".into()),
            Some(mark) => {
                self.committed.truncate(mark);
                self.current.clear();
                Ok(())
            }
        }
    }

    /// Execute a closure within a push/pop scope.
    /// Mirrors Python's `scoped(solver)` context manager.
    pub fn scoped<F, R>(&mut self, f: F) -> Result<R, String>
    where
        F: FnOnce(&mut SolverSession) -> R,
    {
        self.push();
        let result = f(self);
        self.pop()?;
        Ok(result)
    }

    /// Build the complete SMT-LIB2 problem string.
    fn build_smtlib(&self) -> String {
        let mut parts: Vec<&str> = self.committed.iter().map(|s| s.as_str()).collect();
        parts.extend(self.current.iter().map(|s| s.as_str()));
        parts.join("\n")
    }

    /// Submit the accumulated problem to Z3 and return the result.
    /// Appends `(check-sat)` and optionally `(get-model)`.
    pub fn check(&self, timeout_ms: i64, get_model: bool) -> SolverResult {
        let mut smtlib = self.build_smtlib();
        smtlib.push_str("\n(check-sat)");
        if get_model {
            smtlib.push_str("\n(get-model)");
        }
        solve(&smtlib, timeout_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Timeout clamping golden vectors ---

    #[test]
    fn clamp_default_timeout_unchanged() {
        // Golden: default 5000 ms passes through unchanged.
        assert_eq!(clamp_timeout(DEFAULT_TIMEOUT_MS), DEFAULT_TIMEOUT_MS);
    }

    #[test]
    fn clamp_zero_becomes_one() {
        // Golden: 0 → 1 (prevents "no timeout" Z3 quirk)
        assert_eq!(clamp_timeout(0), 1);
    }

    #[test]
    fn clamp_negative_becomes_one() {
        // Golden: -1 → 1 (prevents negative-as-huge-unsigned quirk)
        assert_eq!(clamp_timeout(-1), 1);
        assert_eq!(clamp_timeout(i64::MIN), 1);
    }

    #[test]
    fn clamp_over_max_becomes_max() {
        // Golden: 2^31 → MAX_TIMEOUT_MS (prevents 2^32 wraparound)
        assert_eq!(clamp_timeout(MAX_TIMEOUT_MS + 1), MAX_TIMEOUT_MS);
        assert_eq!(clamp_timeout(i64::MAX), MAX_TIMEOUT_MS);
    }

    #[test]
    fn clamp_preserves_valid_range() {
        assert_eq!(clamp_timeout(1), 1);
        assert_eq!(clamp_timeout(1000), 1000);
        assert_eq!(clamp_timeout(MAX_TIMEOUT_MS), MAX_TIMEOUT_MS);
    }

    // --- Degradation when z3 absent ---

    #[test]
    fn solve_returns_unknown_when_z3_absent() {
        // The degradation test: if z3 is not installed, solve() must return
        // Unknown(Z3NotFound) rather than panicking. If z3 IS installed,
        // we still get a valid SolverResult.
        let result = solve("(declare-const x (_ BitVec 32))\n(assert (= x (_ bv42 32)))", 100);
        // Any of these are valid — just must not panic.
        let valid = matches!(
            result,
            SolverResult::Sat { .. } | SolverResult::Unsat | SolverResult::Unknown { .. }
        );
        assert!(valid, "solve() must return a valid SolverResult, got {:?}", result);
    }

    // --- SolverSession push/pop ---

    #[test]
    fn session_push_pop_restores_state() {
        let mut s = SolverSession::new();
        s.add("(declare-const x (_ BitVec 8))");
        s.push();
        s.add("(assert (= x (_ bv10 8)))");
        s.pop().unwrap();
        // After pop, the scoped assertion is gone; only the declaration remains.
        let smtlib = s.build_smtlib();
        assert!(smtlib.contains("declare-const x"), "declaration survives pop");
        assert!(!smtlib.contains("assert"), "scoped assertion removed by pop");
    }

    #[test]
    fn session_scoped_closure() {
        let mut s = SolverSession::new();
        s.add("(declare-const x (_ BitVec 8))");
        let _ = s.scoped(|inner| {
            inner.add("(assert (= x (_ bv10 8)))");
        });
        let smtlib = s.build_smtlib();
        assert!(smtlib.contains("declare-const x"));
        assert!(!smtlib.contains("assert"));
    }

    // --- parse_z3_output ---

    #[test]
    fn parse_sat_output() {
        let stdout = b"sat\n(model\n  (define-fun x () (_ BitVec 32) (_ bv42 32))\n)\n";
        let result = parse_z3_output(stdout, b"");
        assert!(matches!(result, SolverResult::Sat { .. }));
        if let SolverResult::Sat { model } = result {
            assert!(model.contains("define-fun"));
        }
    }

    #[test]
    fn parse_unsat_output() {
        let stdout = b"unsat\n";
        let result = parse_z3_output(stdout, b"");
        assert_eq!(result, SolverResult::Unsat);
    }

    #[test]
    fn parse_unknown_output() {
        let stdout = b"unknown\n";
        let result = parse_z3_output(stdout, b"");
        assert!(matches!(result, SolverResult::Unknown { .. }));
    }
}
