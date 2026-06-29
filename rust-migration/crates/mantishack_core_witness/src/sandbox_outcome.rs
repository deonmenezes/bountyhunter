//! Map a sandbox execution's `sandbox_info` dict to a `WitnessOutcome`.
//!
//! Faithful Rust port of core/witness/sandbox_outcome.py.
//!
//! The sandbox layer (`core/sandbox/observe.py::_interpret_result`) already
//! classifies post-execution state into a plain dict. This module is the
//! thin adapter that turns that dict into the `WitnessOutcome` enum plus a
//! structured `outcome_detail` payload.
//!
//! `core.witness` does not import `core.sandbox` — the function takes a
//! plain dict so the dependency arrow stays clean. Producers grab the dict
//! off the `CompletedProcess` (`result.sandbox_info`) and pass it in.

use std::collections::HashMap;

use serde_json::Value;

use crate::types::WitnessOutcome;

/// Classify a sandboxed execution as a `(WitnessOutcome, outcome_detail)` pair.
///
/// Precedence (most-informative wins):
///
/// 1. **Sanitizer report** → `SANITIZER_REPORT`. ASAN with `halt_on_error=0`
///    can fire without abnormal exit; we still call that a sanitizer outcome.
/// 2. **Crash signal** (`crashed=true`, or signal in SIGSEGV/SIGABRT etc.)
///    → `EXIT_SIGNAL`.
/// 3. **Resource-exceeded** (SIGXCPU / SIGXFSZ) → `EXIT_SIGNAL` with
///    `resource_exceeded=true` in detail.
/// 4. **Seccomp kill** (SIGSYS) → `EXIT_SIGNAL` with `seccomp_killed=true`.
/// 5. **Sandbox enforcement** (`blocked` non-empty, no other class fired)
///    → `NO_OBVIOUS_EFFECT` with `blocked` in detail.
/// 6. **Nothing classifiable** → `NO_OBVIOUS_EFFECT`.
///
/// # Arguments
/// * `sandbox_info` — Dict produced by `core/sandbox/observe.py`. May be
///   `None` if the sandbox attached no info — treated as "nothing classifiable".
/// * `returncode` — Optional process exit code for inclusion in `outcome_detail`.
///
/// # Returns
/// `(outcome, detail)` where detail is a flat `HashMap<String, Value>` carrying
/// only present fields (absent → omitted), matching Python's convention.
pub fn outcome_from_sandbox_info(
    sandbox_info: Option<&HashMap<String, Value>>,
    returncode: Option<i64>,
) -> (WitnessOutcome, HashMap<String, Value>) {
    let mut detail: HashMap<String, Value> = HashMap::new();
    if let Some(rc) = returncode {
        detail.insert("returncode".to_string(), Value::Number(rc.into()));
    }

    let empty = HashMap::new();
    let info = sandbox_info.unwrap_or(&empty);

    fn str_val(info: &HashMap<String, Value>, key: &str) -> Option<String> {
        info.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    fn bool_val(info: &HashMap<String, Value>, key: &str) -> bool {
        info.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
    }

    fn list_val(info: &HashMap<String, Value>, key: &str) -> Option<Vec<Value>> {
        info.get(key).and_then(|v| v.as_array()).map(|a| a.clone())
    }

    // 1. Sanitizer wins: directly identifies a bug class even without crash.
    if let Some(sanitizer) = str_val(info, "sanitizer") {
        detail.insert("sanitizer".to_string(), Value::String(sanitizer));
        if bool_val(info, "crashed") {
            detail.insert("crashed".to_string(), Value::Bool(true));
        }
        if let Some(sig) = str_val(info, "signal") {
            detail.insert("signal".to_string(), Value::String(sig));
        }
        if let Some(ev) = info.get("evidence") {
            detail.insert("evidence".to_string(), ev.clone());
        }
        return (WitnessOutcome::SanitizerReport, detail);
    }

    // 2–4. Signal-killed (crash, resource-exceeded, seccomp).
    if let Some(sig) = str_val(info, "signal") {
        detail.insert("signal".to_string(), Value::String(sig));
        if let Some(sig_num) = info.get("signal_num") {
            detail.insert("signal_num".to_string(), sig_num.clone());
        }
        if bool_val(info, "crashed") {
            detail.insert("crashed".to_string(), Value::Bool(true));
        }
        if bool_val(info, "resource_exceeded") {
            detail.insert("resource_exceeded".to_string(), Value::Bool(true));
        }
        if bool_val(info, "seccomp_killed") {
            detail.insert("seccomp_killed".to_string(), Value::Bool(true));
        }
        if let Some(ev) = info.get("evidence") {
            detail.insert("evidence".to_string(), ev.clone());
        }
        if let Some(blocked) = list_val(info, "blocked") {
            detail.insert("blocked".to_string(), Value::Array(blocked));
        }
        return (WitnessOutcome::ExitSignal, detail);
    }

    // crashed without a signal (defensive — mirrors Python).
    if bool_val(info, "crashed") {
        detail.insert("crashed".to_string(), Value::Bool(true));
        if let Some(ev) = info.get("evidence") {
            detail.insert("evidence".to_string(), ev.clone());
        }
        return (WitnessOutcome::ExitSignal, detail);
    }

    // 5. Sandbox enforcement only (no crash, no sanitizer).
    if let Some(blocked) = list_val(info, "blocked") {
        if !blocked.is_empty() {
            detail.insert("blocked".to_string(), Value::Array(blocked));
            if let Some(ev) = info.get("evidence") {
                detail.insert("evidence".to_string(), ev.clone());
            }
            return (WitnessOutcome::NoObviousEffect, detail);
        }
    }

    // 6. Nothing observed.
    if let Some(ev) = info.get("evidence") {
        detail.insert("evidence".to_string(), ev.clone());
    }
    (WitnessOutcome::NoObviousEffect, detail)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    // -- Golden vectors produced by running Python --

    #[test]
    fn test_sanitizer_report_with_crash_and_signal() {
        // Python: outcome_from_sandbox_info({'sanitizer':'asan','crashed':True,'signal':'SIGSEGV'})
        // → (SANITIZER_REPORT, {'sanitizer':'asan','crashed':True,'signal':'SIGSEGV'})
        let info = make_info(&[
            ("sanitizer", Value::String("asan".to_string())),
            ("crashed", Value::Bool(true)),
            ("signal", Value::String("SIGSEGV".to_string())),
        ]);
        let (outcome, detail) = outcome_from_sandbox_info(Some(&info), None);
        assert_eq!(outcome, WitnessOutcome::SanitizerReport);
        assert_eq!(detail.get("sanitizer").and_then(|v| v.as_str()), Some("asan"));
        assert_eq!(detail.get("crashed").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(detail.get("signal").and_then(|v| v.as_str()), Some("SIGSEGV"));
    }

    #[test]
    fn test_exit_signal_crash() {
        // Python: outcome_from_sandbox_info({'signal':'SIGSEGV','signal_num':11,'crashed':True})
        // → (EXIT_SIGNAL, {'signal':'SIGSEGV','signal_num':11,'crashed':True})
        let info = make_info(&[
            ("signal", Value::String("SIGSEGV".to_string())),
            ("signal_num", Value::Number(11.into())),
            ("crashed", Value::Bool(true)),
        ]);
        let (outcome, detail) = outcome_from_sandbox_info(Some(&info), None);
        assert_eq!(outcome, WitnessOutcome::ExitSignal);
        assert_eq!(detail.get("signal").and_then(|v| v.as_str()), Some("SIGSEGV"));
        assert_eq!(detail.get("signal_num").and_then(|v| v.as_i64()), Some(11));
    }

    #[test]
    fn test_exit_signal_resource_exceeded() {
        // Python: outcome_from_sandbox_info({'signal':'SIGXCPU','resource_exceeded':True})
        // → (EXIT_SIGNAL, {'signal':'SIGXCPU','resource_exceeded':True})
        let info = make_info(&[
            ("signal", Value::String("SIGXCPU".to_string())),
            ("resource_exceeded", Value::Bool(true)),
        ]);
        let (outcome, detail) = outcome_from_sandbox_info(Some(&info), None);
        assert_eq!(outcome, WitnessOutcome::ExitSignal);
        assert_eq!(
            detail.get("resource_exceeded").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn test_exit_signal_seccomp() {
        // Python: outcome_from_sandbox_info({'signal':'SIGSYS','seccomp_killed':True})
        // → (EXIT_SIGNAL, {'signal':'SIGSYS','seccomp_killed':True})
        let info = make_info(&[
            ("signal", Value::String("SIGSYS".to_string())),
            ("seccomp_killed", Value::Bool(true)),
        ]);
        let (outcome, detail) = outcome_from_sandbox_info(Some(&info), None);
        assert_eq!(outcome, WitnessOutcome::ExitSignal);
        assert_eq!(
            detail.get("seccomp_killed").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn test_blocked_sandbox_enforcement() {
        // Python: outcome_from_sandbox_info({'blocked':['net','write']})
        // → (NO_OBVIOUS_EFFECT, {'blocked':['net','write']})
        let info = make_info(&[(
            "blocked",
            Value::Array(vec![
                Value::String("net".to_string()),
                Value::String("write".to_string()),
            ]),
        )]);
        let (outcome, detail) = outcome_from_sandbox_info(Some(&info), None);
        assert_eq!(outcome, WitnessOutcome::NoObviousEffect);
        let blocked = detail.get("blocked").and_then(|v| v.as_array()).unwrap();
        assert_eq!(blocked.len(), 2);
    }

    #[test]
    fn test_none_info_no_obvious_effect() {
        // Python: outcome_from_sandbox_info(None) → (NO_OBVIOUS_EFFECT, {})
        let (outcome, detail) = outcome_from_sandbox_info(None, None);
        assert_eq!(outcome, WitnessOutcome::NoObviousEffect);
        assert!(detail.is_empty());
    }

    #[test]
    fn test_empty_info_no_obvious_effect() {
        // Python: outcome_from_sandbox_info({}) → (NO_OBVIOUS_EFFECT, {})
        let info = HashMap::new();
        let (outcome, detail) = outcome_from_sandbox_info(Some(&info), None);
        assert_eq!(outcome, WitnessOutcome::NoObviousEffect);
        assert!(detail.is_empty());
    }

    #[test]
    fn test_returncode_in_detail() {
        // Python: outcome_from_sandbox_info(None, returncode=0)
        // → (NO_OBVIOUS_EFFECT, {'returncode': 0})
        let (outcome, detail) = outcome_from_sandbox_info(None, Some(0));
        assert_eq!(outcome, WitnessOutcome::NoObviousEffect);
        assert_eq!(detail.get("returncode").and_then(|v| v.as_i64()), Some(0));
    }

    #[test]
    fn test_crashed_without_signal() {
        // Python: outcome_from_sandbox_info({'crashed':True,'evidence':'core dump'})
        // → (EXIT_SIGNAL, {'crashed':True,'evidence':'core dump'})
        let info = make_info(&[
            ("crashed", Value::Bool(true)),
            ("evidence", Value::String("core dump".to_string())),
        ]);
        let (outcome, detail) = outcome_from_sandbox_info(Some(&info), None);
        assert_eq!(outcome, WitnessOutcome::ExitSignal);
        assert_eq!(detail.get("crashed").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            detail.get("evidence").and_then(|v| v.as_str()),
            Some("core dump")
        );
    }

    #[test]
    fn test_flag_captured_not_derivable_from_sandbox_info() {
        // FLAG_CAPTURED is not emitted by this function (requires external oracle).
        // Verify that no sandbox_info combination produces FLAG_CAPTURED.
        let info = make_info(&[("flag_captured", Value::Bool(true))]);
        let (outcome, _) = outcome_from_sandbox_info(Some(&info), None);
        assert_ne!(outcome, WitnessOutcome::FlagCaptured);
    }
}
