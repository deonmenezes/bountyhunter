//! Parity oracle tests for mantishack_semgrep.
//!
//! Golden vectors are derived by reading the Python parsing code precisely
//! (the Python package cannot be imported in this environment) and constructing
//! expected outputs from first principles, verified against the Python logic.
//!
//! Tests cover:
//!   * `parse_sarif` — 8 cases (dict/string message, no-location, default level,
//!     empty/malformed input, multiple findings)
//!   * `parse_json_output` — 3 cases (full, empty text, malformed JSON)
//!   * `build_cmd` — 3 cases (basic argv order, with json_output, with extra_args)
//!   * `get_safe_env` — 1 case (unsafe keys stripped)
//!   * `to_findings` — 2 cases (basic, empty-message fallback)
//!   * `to_coverage_record` — 2 cases (basic, returns None with no files)
//!   * `config_to_name` — 5 sub-cases

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::coverage::to_coverage_record;
    use crate::findings::to_findings;
    use crate::models::{parse_json_output, parse_sarif, SemgrepFinding, SemgrepResult};
    use crate::runner::{build_cmd, config_to_name, get_safe_env, UNSAFE_ENV_KEYS};

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_sarif(results_json: &str) -> String {
        format!(r#"{{"runs":[{{"results":[{}]}}]}}"#, results_json)
    }

    fn make_finding_json(
        rule_id: &str,
        message: &str,
        level: &str,
        uri: &str,
        start_line: u32,
        start_col: u32,
        end_line: u32,
        end_col: u32,
    ) -> String {
        format!(
            r#"{{
              "ruleId": "{}",
              "message": {{"text": "{}"}},
              "level": "{}",
              "locations": [{{
                "physicalLocation": {{
                  "artifactLocation": {{"uri": "{}"}},
                  "region": {{
                    "startLine": {},
                    "startColumn": {},
                    "endLine": {},
                    "endColumn": {}
                  }}
                }}
              }}]
            }}"#,
            rule_id, message, level, uri, start_line, start_col, end_line, end_col
        )
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 1: single finding with dict message {"text": "..."}
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc1_parse_sarif_dict_message() {
        let sarif = make_sarif(&make_finding_json(
            "python.lang.security.injection.eval-injection",
            "Detected eval injection.",
            "error",
            "src/app.py",
            42, 5, 42, 20,
        ));
        let findings = parse_sarif(&sarif);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.rule_id, "python.lang.security.injection.eval-injection");
        assert_eq!(f.message, "Detected eval injection.");
        assert_eq!(f.level, "error");
        assert_eq!(f.file, "src/app.py");
        assert_eq!(f.line, 42);
        assert_eq!(f.column, 5);
        assert_eq!(f.line_end, 42);
        assert_eq!(f.column_end, 20);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 2: single finding with string message
    // Python: `elif isinstance(msg, str): message = msg`
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc2_parse_sarif_string_message() {
        let sarif = format!(
            r#"{{"runs":[{{"results":[{{
              "ruleId":"test.rule",
              "message":"String message here",
              "level":"warning",
              "locations":[{{"physicalLocation":{{
                "artifactLocation":{{"uri":"foo.py"}},
                "region":{{"startLine":10,"startColumn":1,"endLine":10,"endColumn":5}}
              }}}}]
            }}]}}]}}"#
        );
        let findings = parse_sarif(&sarif);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].message, "String message here");
        assert_eq!(findings[0].level, "warning");
        assert_eq!(findings[0].file, "foo.py");
        assert_eq!(findings[0].line, 10);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 3: missing "level" → defaults to "warning"
    // Python: level = result.get("level", "warning")
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc3_parse_sarif_default_level() {
        let sarif = format!(
            r#"{{"runs":[{{"results":[{{
              "ruleId":"rule.x",
              "message":{{"text":"msg"}},
              "locations":[{{"physicalLocation":{{
                "artifactLocation":{{"uri":"a.py"}},
                "region":{{"startLine":1,"startColumn":1,"endLine":1,"endColumn":1}}
              }}}}]
            }}]}}]}}"#
        );
        let findings = parse_sarif(&sarif);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].level, "warning");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 4: no "locations" key → file="", line=0, all coords 0
    // Python: locations = result.get("locations") or []
    //         if locations and isinstance(locations[0], dict): ...
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc4_parse_sarif_no_locations() {
        let sarif = r#"{"runs":[{"results":[{"ruleId":"rule.y","message":{"text":"oops"},"level":"note"}]}]}"#;
        let findings = parse_sarif(sarif);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.file, "");
        assert_eq!(f.line, 0);
        assert_eq!(f.column, 0);
        assert_eq!(f.line_end, 0);
        assert_eq!(f.column_end, 0);
        assert_eq!(f.rule_id, "rule.y");
        assert_eq!(f.message, "oops");
        assert_eq!(f.level, "note");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 5: empty results array → empty vec
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc5_parse_sarif_empty_results() {
        let sarif = r#"{"runs":[{"results":[]}]}"#;
        assert!(parse_sarif(sarif).is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 6: empty / whitespace text → empty vec
    // Python: if not text or not text.strip(): return []
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc6_parse_sarif_empty_text() {
        assert!(parse_sarif("").is_empty());
        assert!(parse_sarif("   \n\t  ").is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 7: malformed JSON → empty vec (no panic)
    // Python: except (json.JSONDecodeError, ValueError): return []
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc7_parse_sarif_malformed_json() {
        assert!(parse_sarif("not valid json").is_empty());
        assert!(parse_sarif("{broken}").is_empty());
        assert!(parse_sarif("null").is_empty());   // valid JSON but not an object with "runs"
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 8: multiple findings across two SARIF runs
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc8_parse_sarif_multiple_findings() {
        let f1 = make_finding_json("rule.a", "msg A", "error", "a.py", 1, 1, 1, 5);
        let f2 = make_finding_json("rule.b", "msg B", "warning", "b.py", 99, 3, 99, 10);
        let sarif = format!(
            r#"{{"runs":[{{"results":[{}]}},{{"results":[{}]}}]}}"#,
            f1, f2
        );
        let findings = parse_sarif(&sarif);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "rule.a");
        assert_eq!(findings[0].file, "a.py");
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[1].rule_id, "rule.b");
        assert_eq!(findings[1].file, "b.py");
        assert_eq!(findings[1].line, 99);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 9: parse_json_output full case
    // Python normalises: paths.scanned → sorted files_examined,
    //                    errors[].message → reason, filters entries without path
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc9_parse_json_output_full() {
        let json = r#"{
          "version": "1.47.0",
          "paths": {"scanned": ["b.py", "a.py", "c.py"]},
          "errors": [
            {"path": "broken.py", "message": "parse error"},
            {"path": "also_broken.py", "message": "timeout"}
          ]
        }"#;
        let out = parse_json_output(json);
        // files_examined is sorted
        assert_eq!(out.files_examined, vec!["a.py", "b.py", "c.py"]);
        assert_eq!(out.semgrep_version, "1.47.0");
        assert_eq!(out.files_failed.len(), 2);
        let ff0 = &out.files_failed[0];
        assert_eq!(ff0.get("path").map(String::as_str), Some("broken.py"));
        assert_eq!(ff0.get("reason").map(String::as_str), Some("parse error"));
        let ff1 = &out.files_failed[1];
        assert_eq!(ff1.get("path").map(String::as_str), Some("also_broken.py"));
        assert_eq!(ff1.get("reason").map(String::as_str), Some("timeout"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 10: parse_json_output with empty text → all-empty defaults
    // Python: if not text or not text.strip(): return out (empty)
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc10_parse_json_output_empty_text() {
        let out = parse_json_output("");
        assert!(out.files_examined.is_empty());
        assert!(out.files_failed.is_empty());
        assert_eq!(out.semgrep_version, "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 11: parse_json_output malformed JSON → empty defaults (no panic)
    // Python: except (json.JSONDecodeError, ValueError): return out
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc11_parse_json_output_malformed() {
        let out = parse_json_output("not json");
        assert!(out.files_examined.is_empty());
        assert!(out.files_failed.is_empty());
        assert_eq!(out.semgrep_version, "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 12: build_cmd basic argv order
    // Expected: semgrep scan --config p/security-audit --quiet --metrics off
    //   --error --sarif --timeout 60 /src
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc12_build_cmd_basic_argv_order() {
        let cmd = build_cmd(
            Path::new("/src"),
            "p/security-audit",
            None,                              // no json_output_path
            60,                                // rule_timeout
            Some("/usr/local/bin/semgrep"),    // explicit bin
            None,                              // no extra_args
        );
        assert_eq!(
            cmd,
            vec![
                "/usr/local/bin/semgrep",
                "scan",
                "--config", "p/security-audit",
                "--quiet",
                "--metrics", "off",
                "--error",
                "--sarif",
                "--timeout", "60",
                // target is the final argument
                "/src",
            ]
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 13: build_cmd with --json-output (inserted before target)
    // Python: if json_output_path is not None: cmd.extend(["--json-output", str(...)])
    //         cmd.append(str(target))   ← target always last
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc13_build_cmd_with_json_output() {
        let cmd = build_cmd(
            Path::new("/repo"),
            "p/ci",
            Some(Path::new("/tmp/out.json")),
            60,
            Some("semgrep"),
            None,
        );
        // --json-output must appear before the target
        let json_idx = cmd.iter().position(|s| s == "--json-output").expect("--json-output missing");
        let target_idx = cmd.iter().position(|s| s == "/repo").expect("target missing");
        assert!(json_idx < target_idx, "--json-output must precede target");
        assert_eq!(cmd[json_idx + 1], "/tmp/out.json");
        // target is the last element
        assert_eq!(cmd.last().map(String::as_str), Some("/repo"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 14: build_cmd with extra_args (inserted before target)
    // Python: if extra_args: cmd.extend(extra_args)
    //         cmd.append(str(target))
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc14_build_cmd_with_extra_args() {
        let extra = vec!["--exclude".to_string(), "*.test.py".to_string()];
        let cmd = build_cmd(
            Path::new("/app"),
            "r/owasp-top-ten",
            None,
            120,
            Some("semgrep"),
            Some(&extra),
        );
        let excl_idx = cmd.iter().position(|s| s == "--exclude").expect("--exclude missing");
        let target_idx = cmd.iter().position(|s| s == "/app").expect("target missing");
        assert!(excl_idx < target_idx, "--exclude must precede target");
        assert_eq!(cmd[excl_idx + 1], "*.test.py");
        assert_eq!(cmd.last().map(String::as_str), Some("/app"));
        // argv: [semgrep, scan, --config, r/owasp-top-ten, --quiet,
        //        --metrics, off, --error, --sarif, --timeout, 120, ...]
        assert_eq!(cmd[9], "--timeout");
        assert_eq!(cmd[10], "120");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 15: get_safe_env strips TERMINAL EDITOR VISUAL BROWSER PAGER
    // Python: MantishackConfig.get_safe_env() strips those five keys
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc15_get_safe_env_strips_unsafe_keys() {
        // Inject risky env vars for this test.  std::env::set_var is not thread-safe
        // on all platforms, but for a unit test this is acceptable.
        unsafe {
            std::env::set_var("TERMINAL", "xterm");
            std::env::set_var("EDITOR", "vim");
            std::env::set_var("VISUAL", "code");
            std::env::set_var("BROWSER", "firefox");
            std::env::set_var("PAGER", "less");
            std::env::set_var("HOME", "/home/test");
        }

        let safe = get_safe_env();

        // None of the unsafe keys must survive.
        for key in UNSAFE_ENV_KEYS {
            assert!(
                !safe.contains_key(*key),
                "get_safe_env must strip {} but it was present",
                key
            );
        }
        // Safe keys are preserved.
        assert!(
            safe.contains_key("HOME"),
            "get_safe_env must preserve HOME"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 16: to_findings basic conversion
    // Python: {"id": "SEMGREP-myrun-1", "file": ..., "line": ...,
    //          "confidence": "medium", "origin": "semgrep", ...}
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc16_to_findings_basic() {
        let finding = SemgrepFinding {
            file: "src/auth.py".to_string(),
            line: 77,
            rule_id: "python.lang.security.sql-injection".to_string(),
            message: "SQL injection detected.".to_string(),
            column: 1,
            line_end: 77,
            column_end: 30,
            level: "error".to_string(),
        };
        let result = SemgrepResult {
            name: "myrun".to_string(),
            findings: vec![finding],
            ..Default::default()
        };
        let out = to_findings(&[result]);
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f["id"], "SEMGREP-myrun-1");
        assert_eq!(f["file"], "src/auth.py");
        assert_eq!(f["line"], 77);
        assert_eq!(f["confidence"], "medium");
        assert_eq!(f["origin"], "semgrep");
        assert_eq!(f["rule"], "python.lang.security.sql-injection");
        assert_eq!(f["level"], "error");
        assert_eq!(f["description"], "SQL injection detected.");
        assert_eq!(f["function"], "");
        assert_eq!(f["vuln_type"], "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 17: to_findings empty message → "Match for {rule_id}"
    // Python: f.message or f"Match for {f.rule_id}"
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc17_to_findings_empty_message_fallback() {
        let finding = SemgrepFinding {
            file: "x.py".to_string(),
            line: 1,
            rule_id: "my.custom.rule".to_string(),
            message: "".to_string(),
            level: "warning".to_string(),
            ..Default::default()
        };
        let result = SemgrepResult {
            name: "custom".to_string(),
            findings: vec![finding],
            ..Default::default()
        };
        let out = to_findings(&[result]);
        assert_eq!(out[0]["description"], "Match for my.custom.rule");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 18: to_coverage_record basic
    // Python: aggregates files_examined, version, rules_applied, files_failed
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc18_to_coverage_record_basic() {
        let r1 = SemgrepResult {
            name: "injection".to_string(),
            files_examined: vec!["a.py".to_string(), "b.py".to_string()],
            semgrep_version: "1.47.0".to_string(),
            ..Default::default()
        };
        let r2 = SemgrepResult {
            name: "sqli".to_string(),
            files_examined: vec!["b.py".to_string(), "c.py".to_string()],
            semgrep_version: "1.47.0".to_string(),
            ..Default::default()
        };
        let record = to_coverage_record(&[r1, r2], None).expect("expected Some record");

        assert_eq!(record["tool"], "semgrep");
        assert!(record["timestamp"].is_string());

        // files_examined is the sorted union of a.py, b.py, c.py
        let files = record["files_examined"].as_array().unwrap();
        let file_strs: Vec<&str> = files.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(file_strs, vec!["a.py", "b.py", "c.py"]);

        // rules_applied derived from result names in insertion order, deduplicated
        let rules = record["rules_applied"].as_array().unwrap();
        let rule_strs: Vec<&str> = rules.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(rule_strs, vec!["injection", "sqli"]);

        // version from first result
        assert_eq!(record["version"], "1.47.0");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 19: to_coverage_record returns None when no files examined
    // Python: if not files: return None
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc19_to_coverage_record_none_when_empty() {
        let r = SemgrepResult {
            name: "check".to_string(),
            files_examined: vec![],
            ..Default::default()
        };
        assert!(to_coverage_record(&[r], None).is_none());
        assert!(to_coverage_record(&[], None).is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 20: config_to_name various inputs
    // Python: "" → "semgrep", "p/…" → as-is, "category/…" → as-is,
    //         "/path/rules.yaml" → "rules.yaml", "rules" → "rules"
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc20_config_to_name() {
        assert_eq!(config_to_name(""), "semgrep");
        assert_eq!(config_to_name("p/security-audit"), "p/security-audit");
        assert_eq!(config_to_name("category/injection"), "category/injection");
        assert_eq!(config_to_name("/path/to/rules.yaml"), "rules.yaml");
        assert_eq!(config_to_name("rules"), "rules");
        assert_eq!(config_to_name("./local/my-rules"), "my-rules");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 21: SemgrepResult.ok() — returncode 0 or 1 + no errors → true
    // Python: returncode in (0, 1) and not self.errors
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc21_semgrep_result_ok_property() {
        let ok0 = SemgrepResult { returncode: 0, ..Default::default() };
        let ok1 = SemgrepResult { returncode: 1, ..Default::default() };
        let bad = SemgrepResult { returncode: 2, ..Default::default() };
        let with_errors = SemgrepResult {
            returncode: 0,
            errors: vec!["something failed".to_string()],
            ..Default::default()
        };
        assert!(ok0.ok());
        assert!(ok1.ok());
        assert!(!bad.ok());
        assert!(!with_errors.ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 22: SemgrepFinding.to_dict() keys match Python to_dict() exactly
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc22_semgrep_finding_to_dict_keys() {
        let f = SemgrepFinding {
            file: "x.py".to_string(),
            line: 5,
            rule_id: "r.id".to_string(),
            message: "msg".to_string(),
            column: 1,
            line_end: 6,
            column_end: 10,
            level: "warning".to_string(),
        };
        let d = f.to_dict();
        let expected_keys = ["file", "line", "column", "line_end", "column_end", "rule_id", "message", "level"];
        for key in &expected_keys {
            assert!(d.get(key).is_some(), "missing key: {}", key);
        }
        assert_eq!(d["file"], "x.py");
        assert_eq!(d["line"], 5);
        assert_eq!(d["column"], 1);
        assert_eq!(d["line_end"], 6);
        assert_eq!(d["column_end"], 10);
        assert_eq!(d["rule_id"], "r.id");
        assert_eq!(d["message"], "msg");
        assert_eq!(d["level"], "warning");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 23: run_rule when semgrep unavailable → error result
    // Python: return SemgrepResult(..., errors=["semgrep is not installed ..."],
    //           returncode=-1)
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc23_run_rule_unavailable_semgrep() {
        use crate::runner::{run_rule, RunRuleArgs};

        // Only run this assertion when semgrep is absent from PATH.
        // When semgrep IS installed we can't test the "unavailable" path.
        if crate::runner::is_available() {
            return; // skip — semgrep is present in this environment
        }

        let result = run_rule(RunRuleArgs {
            target: Path::new("/tmp/fake"),
            config: "p/security-audit",
            name: "",
            timeout: 10,
            rule_timeout: 5,
            env: None,
            json_output_path: None,
            semgrep_bin: None,
            extra_args: None,
        });
        assert_eq!(result.returncode, -1);
        assert!(!result.errors.is_empty());
        assert!(result.errors[0].contains("semgrep"));
        assert!(!result.ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 24: build_cmd — rule_timeout is correctly embedded
    // Python: "--timeout", str(rule_timeout)  (position 9 and 10 in the argv)
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc24_build_cmd_rule_timeout_position() {
        let cmd = build_cmd(
            Path::new("/target"),
            "p/owasp",
            None,
            300, // rule_timeout
            Some("semgrep"),
            None,
        );
        // Fixed positions in argv:
        // 0=semgrep 1=scan 2=--config 3=p/owasp 4=--quiet 5=--metrics 6=off
        // 7=--error 8=--sarif 9=--timeout 10=300 11=/target
        assert_eq!(cmd[9], "--timeout");
        assert_eq!(cmd[10], "300");
        assert_eq!(cmd.last().map(String::as_str), Some("/target"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden case 25: parse_json_output — error entries without "path" are filtered
    // Python: for e in errors if isinstance(e, dict) and e.get("path")
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn gc25_parse_json_output_filters_errors_without_path() {
        let json = r#"{
          "version": "1.50.0",
          "paths": {"scanned": ["f.py"]},
          "errors": [
            {"message": "no path key here"},
            {"path": "", "message": "empty path"},
            {"path": "real.py", "message": "actual error"}
          ]
        }"#;
        let out = parse_json_output(json);
        assert_eq!(out.files_failed.len(), 1);
        assert_eq!(out.files_failed[0]["path"], "real.py");
        assert_eq!(out.files_failed[0]["reason"], "actual error");
    }
}
