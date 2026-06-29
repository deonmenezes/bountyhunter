//! Parity-oracle tests for `mantishack_static_codeql`.
//!
//! Golden vectors are derived by reading `codeql/env.py` precisely.  The
//! Python package cannot be imported in this build environment, so every
//! expected value is cross-checked against the Python source and stated
//! explicitly — no assumptions.
//!
//! Coverage:
//!   * `detect_codeql` — 7 cases (mode routing, env-var logic, path lookup)
//!   * `run_codeql_version` — 1 case (nonexistent binary → None)
//!   * `CodeQLEnv.to_dict` — 2 cases (full values, null fields)
//!   * `UNSAFE_ENV_KEYS` — 1 case (required keys present)
//!   Total: 11 golden cases

#[cfg(test)]
mod tests {
    use crate::env::{detect_codeql, run_codeql_version, CodeQLEnv, UNSAFE_ENV_KEYS};

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 1: mode="disabled" → available=false, canonical reason string.
    // Python: CodeQLEnv(mode="disabled", available=False,
    //           reason="CodeQL mode is disabled by configuration.")
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc1_detect_disabled_mode() {
        let env = detect_codeql(Some("disabled"));
        assert_eq!(env.mode, "disabled");
        assert!(!env.available);
        assert!(env.cli_path.is_none());
        assert!(env.version.is_none());
        assert_eq!(
            env.reason.as_deref(),
            Some("CodeQL mode is disabled by configuration.")
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 2: mode=None → Python `mode or "disabled"` → "disabled"
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc2_detect_none_mode_defaults_to_disabled() {
        let env = detect_codeql(None);
        assert_eq!(env.mode, "disabled");
        assert!(!env.available);
        assert_eq!(
            env.reason.as_deref(),
            Some("CodeQL mode is disabled by configuration.")
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 3: mode="" (falsy string) → "disabled"
    // Python: "" is falsy → mode = "" or "disabled" = "disabled"
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc3_detect_empty_mode_defaults_to_disabled() {
        let env = detect_codeql(Some(""));
        assert_eq!(env.mode, "disabled");
        assert!(!env.available);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 4: unknown mode → mode="detect", reason contains
    //   "Unknown mode value 'bogus', defaulting to 'detect'."
    // Python: return CodeQLEnv(mode="detect", available=False,
    //           reason=f"Unknown mode value {mode!r}, defaulting to 'detect'.")
    // Note: Python's repr of a str uses single quotes.
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc4_detect_unknown_mode() {
        let env = detect_codeql(Some("bogus"));
        assert_eq!(env.mode, "detect");
        assert!(!env.available);
        let reason = env.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("Unknown mode value"),
            "reason should contain 'Unknown mode value': {}",
            reason
        );
        assert!(
            reason.contains("bogus"),
            "reason should contain the bad mode value: {}",
            reason
        );
        assert!(
            reason.contains("defaulting to 'detect'"),
            "reason should contain fallback notice: {}",
            reason
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 5: CODEQL_CLI points to nonexistent file → reason mentions
    //   "not executable".
    // Python: reason = f"CODEQL_CLI is set to {env_cli!r} but the file is not
    //           executable."  (fires when is_file() → False)
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc5_detect_codeql_cli_nonexistent_path() {
        unsafe {
            std::env::set_var("CODEQL_CLI", "/nonexistent/path/to/codeql-binary");
        }
        let env = detect_codeql(Some("detect"));
        unsafe { std::env::remove_var("CODEQL_CLI"); }

        assert!(!env.available);
        let reason = env.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("not executable") || reason.contains("not found"),
            "reason: {}",
            reason
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 6: mode="detect", CODEQL_CLI absent, codeql not on PATH
    //   → reason = "CodeQL CLI not found on PATH and CODEQL_CLI is not set."
    // Python: elif reason is None: reason = "CodeQL CLI not found on PATH..."
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc6_detect_no_codeql_available() {
        unsafe { std::env::remove_var("CODEQL_CLI"); }

        // Guard: skip when codeql IS on PATH (can't fake absence portably).
        if crate::env::which_codeql().is_some() {
            return;
        }

        let env = detect_codeql(Some("detect"));
        assert!(!env.available);
        let reason = env.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("not found on PATH"),
            "reason: {}",
            reason
        );
        assert!(
            reason.contains("CODEQL_CLI is not set"),
            "reason: {}",
            reason
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 7: mode="require" behaves identically to "detect" for
    //   the availability lookup path (mode is stored verbatim in the result).
    // Python: only "disabled" short-circuits; "detect"/"require" go through
    //   the same cli_path resolution code.
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc7_detect_require_mode_stored_verbatim() {
        unsafe { std::env::remove_var("CODEQL_CLI"); }

        if crate::env::which_codeql().is_some() {
            return; // codeql installed — can't test unavailable path
        }

        let env = detect_codeql(Some("require"));
        // mode must be stored as "require", not coerced to anything else
        assert_eq!(env.mode, "require");
        assert!(!env.available);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 8: run_codeql_version with nonexistent binary → None.
    // Python: except Exception: return None  (covers OSError from spawn failure)
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc8_run_codeql_version_nonexistent_binary() {
        let result = run_codeql_version("/absolutely/nonexistent/codeql", 2);
        assert!(result.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 9: CodeQLEnv.to_dict() contains all 6 keys with correct types.
    // Python: dataclasses.asdict(env) produces a flat dict with exactly these
    //   keys: mode, available, cli_path, version, queries, reason.
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc9_codeql_env_to_dict_all_keys() {
        let env = CodeQLEnv {
            mode: "detect".to_string(),
            available: true,
            cli_path: Some("/usr/bin/codeql".to_string()),
            version: Some("CodeQL command-line toolchain release 2.15.0".to_string()),
            queries: Some("/opt/codeql-queries".to_string()),
            reason: None,
        };
        let d = env.to_dict();

        // All 6 keys must be present (matches Python dataclasses.asdict field order).
        for key in &["mode", "available", "cli_path", "version", "queries", "reason"] {
            assert!(d.contains_key(*key), "missing key in to_dict(): {}", key);
        }

        assert_eq!(d["mode"].as_str(), Some("detect"));
        assert_eq!(d["available"].as_bool(), Some(true));
        assert_eq!(d["cli_path"].as_str(), Some("/usr/bin/codeql"));
        assert_eq!(
            d["version"].as_str(),
            Some("CodeQL command-line toolchain release 2.15.0")
        );
        assert_eq!(d["queries"].as_str(), Some("/opt/codeql-queries"));
        assert!(d["reason"].is_null(), "None reason must serialize to null");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 10: CodeQLEnv.to_dict() with all-None optional fields →
    //   JSON null for each.  Python: asdict() preserves None as None (→ null).
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc10_codeql_env_to_dict_null_optional_fields() {
        let env = CodeQLEnv {
            mode: "disabled".to_string(),
            available: false,
            cli_path: None,
            version: None,
            queries: None,
            reason: Some("CodeQL mode is disabled by configuration.".to_string()),
        };
        let d = env.to_dict();

        assert!(d["cli_path"].is_null(), "cli_path None → null");
        assert!(d["version"].is_null(), "version None → null");
        assert!(d["queries"].is_null(), "queries None → null");
        assert_eq!(
            d["reason"].as_str(),
            Some("CodeQL mode is disabled by configuration.")
        );
        assert_eq!(d["available"].as_bool(), Some(false));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 11: UNSAFE_ENV_KEYS contains the five shell-eval keys and
    //   the JVM injection vectors named in the Python source comment.
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc11_unsafe_env_keys_required_entries() {
        // Shell-evaluation risky keys — same as Python `get_safe_env` strips.
        for key in &["TERMINAL", "EDITOR", "VISUAL", "BROWSER", "PAGER"] {
            assert!(
                UNSAFE_ENV_KEYS.contains(key),
                "UNSAFE_ENV_KEYS must include {}",
                key
            );
        }
        // JVM injection vectors explicitly called out in the Python comment.
        for key in &["LD_PRELOAD", "LD_LIBRARY_PATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"] {
            assert!(
                UNSAFE_ENV_KEYS.contains(key),
                "UNSAFE_ENV_KEYS must include {}",
                key
            );
        }
    }
}
