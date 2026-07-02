//! Intent-match judge heuristics for LLM-generated exploits — Rust port of the
//! pure functions in `packages/llm_analysis/intent_match.py`.

use std::sync::OnceLock;

use regex::Regex;

pub const VERDICT_MATCHES: &str = "matches";
pub const VERDICT_OFF_TARGET: &str = "off_target";
pub const VERDICT_UNCERTAIN: &str = "uncertain";

const THRESHOLD_MATCHES_NO_LLM: i64 = 3;

/// One heuristic signal: `(name, Some(matched)/None-for-abstain)`.
pub type Signal<'a> = (&'a str, Option<bool>);

fn basename(path: &str) -> &str {
    path.rsplit_once('/').map(|(_, n)| n).unwrap_or(path)
}

fn any_match(res: &[Regex], text: &str) -> bool {
    res.iter().any(|r| r.is_match(text))
}

fn compile(patterns: &[&str]) -> Vec<Regex> {
    patterns.iter().map(|p| Regex::new(p).unwrap()).collect()
}

/// Does the exploit text mention the finding's file path? (`_file_overlap`)
pub fn file_overlap(finding_file_path: Option<&str>, exploit_code: &str) -> bool {
    let Some(fp) = finding_file_path.filter(|s| !s.is_empty()) else { return false };
    if exploit_code.is_empty() {
        return false;
    }
    if exploit_code.contains(fp) {
        return true;
    }
    let base = basename(fp);
    if base.is_empty() {
        return false;
    }
    Regex::new(&format!(r"\b{}\b", regex::escape(base))).unwrap().is_match(exploit_code)
}

/// Does the exploit text mention the finding's function name? (`_function_overlap`)
pub fn function_overlap(function_name: Option<&str>, exploit_code: &str) -> bool {
    let Some(name) = function_name.filter(|s| !s.is_empty()) else { return false };
    if exploit_code.is_empty() {
        return false;
    }
    Regex::new(&format!(r"\b{}\b", regex::escape(name))).unwrap().is_match(exploit_code)
}

/// Do the compile errors mention the finding's file? (`_compile_error_anchor`)
pub fn compile_error_anchor(finding_file_path: Option<&str>, exploit_compile_errors: Option<&[String]>) -> bool {
    let Some(fp) = finding_file_path.filter(|s| !s.is_empty()) else { return false };
    let Some(errors) = exploit_compile_errors.filter(|e| !e.is_empty()) else { return false };
    let joined = errors.join("\n");
    if joined.contains(fp) {
        return true;
    }
    let base = basename(fp);
    !base.is_empty() && joined.contains(base)
}

fn cwe_buffer_overflow_shape(code: &str) -> bool {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    !code.is_empty() && any_match(RE.get_or_init(|| compile(&[
        r#"[bB]?["'][^"']{1,4}["']\s*\*\s*\d{2,}"#,
        r#"[bB]["'](?:\\x[0-9a-fA-F]{2}){8,}"#,
    ])), code)
}

fn cwe_command_injection_shape(code: &str) -> bool {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    !code.is_empty() && any_match(RE.get_or_init(|| compile(&[
        r#"['"][^'"]*[;&|][^'"]*['"]"#,
        r#"['"][^'"]*(?:\$\([^)]+\)|`[^`]+`)[^'"]*['"]"#,
    ])), code)
}

fn cwe_sql_injection_shape(code: &str) -> bool {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    !code.is_empty() && any_match(RE.get_or_init(|| compile(&[
        r#"(?i)['"]\s*(?:or|OR)\s+[`'"]?1[`'"]?\s*=\s*[`'"]?1"#,
        r#"(?i)--\s*[\\n'";]"#,
        r#"(?i)\bUNION\s+SELECT\b"#,
        r#"(?i)['"]\s*;\s*DROP\s+TABLE\b"#,
    ])), code)
}

fn cwe_xss_shape(code: &str) -> bool {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    !code.is_empty() && any_match(RE.get_or_init(|| compile(&[
        r#"(?i)<\s*script\b"#,
        r#"(?i)\bon\w+\s*=\s*['"]"#,
        r#"(?i)\bjavascript\s*:"#,
        r#"(?i)<\s*img\b[^>]*\bonerror\b"#,
    ])), code)
}

fn cwe_path_traversal_shape(code: &str) -> bool {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    !code.is_empty() && any_match(RE.get_or_init(|| compile(&[
        r#"(?:\.\./){2,}"#,
        r#"%2[eE]%2[eE]%2[fF]"#,
        r#"\.\.\\\\"#,
    ])), code)
}

fn cwe_null_deref_shape(code: &str) -> bool {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    !code.is_empty() && any_match(RE.get_or_init(|| compile(&[
        r#"\bNULL\b"#,
        r#"\(\s*NULL\s*\)"#,
        r#"=\s*None\b"#,
        r#"\(\s*["']{2}\s*[,)]"#,
        r#"=\s*["']{2}\s*[,)]"#,
    ])), code)
}

fn cwe_integer_overflow_shape(code: &str) -> bool {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    !code.is_empty() && any_match(RE.get_or_init(|| compile(&[
        r#"0x[fF]{6,}"#,
        r#"0x7[fF]+\b"#,
        r#"\b2\s*\*\s*\*\s*\d{2,}"#,
        r#"\bMAX_INT\b"#,
        r#"\b(UINT|INT|SIZE_T?)_MAX\b"#,
        r#"sys\.maxsize\b"#,
    ])), code)
}

/// Per-CWE shape match; `None` when no detector exists (`_cwe_shape`).
pub fn cwe_shape(cwe_id: Option<&str>, exploit_code: &str) -> Option<bool> {
    let detector = match cwe_id.filter(|s| !s.is_empty())? {
        "CWE-120" | "CWE-121" | "CWE-122" | "CWE-787" => cwe_buffer_overflow_shape,
        "CWE-78" => cwe_command_injection_shape,
        "CWE-89" => cwe_sql_injection_shape,
        "CWE-79" => cwe_xss_shape,
        "CWE-22" => cwe_path_traversal_shape,
        "CWE-476" => cwe_null_deref_shape,
        "CWE-190" => cwe_integer_overflow_shape,
        _ => return None,
    };
    Some(detector(exploit_code))
}

/// `(matched_count, evaluated_count)` — abstain (None) excluded (`_count_signals`).
pub fn count_signals(signals: &[Signal]) -> (i64, i64) {
    let matched = signals.iter().filter(|(_, v)| *v == Some(true)).count() as i64;
    let evaluated = signals.iter().filter(|(_, v)| v.is_some()).count() as i64;
    (matched, evaluated)
}

/// Decide the verdict from heuristics alone (`_initial_verdict`). A `None`
/// verdict means "ambiguous — escalate to LLM tiebreak".
pub fn initial_verdict(signals: &[Signal]) -> (Option<&'static str>, f64, String) {
    let (matched, evaluated) = count_signals(signals);
    if evaluated == 0 {
        return (Some(VERDICT_UNCERTAIN), 0.0, "no heuristic could evaluate (finding metadata absent)".to_string());
    }
    let fired: Vec<&str> = signals.iter().filter(|(_, v)| *v == Some(true)).map(|(k, _)| *k).collect();
    let not_fired: Vec<&str> = signals.iter().filter(|(_, v)| *v == Some(false)).map(|(k, _)| *k).collect();

    if matched == 0 {
        return (Some(VERDICT_OFF_TARGET), 0.85, format!("no heuristics matched ({evaluated} evaluated); exploit appears to target a different bug"));
    }
    if matched >= THRESHOLD_MATCHES_NO_LLM {
        return (Some(VERDICT_MATCHES), 0.9, format!("{matched}/{evaluated} heuristics matched: {}", fired.join(", ")));
    }
    if matched == evaluated && evaluated >= 2 {
        return (Some(VERDICT_MATCHES), 0.8, format!("all {evaluated} evaluated heuristics matched: {}", fired.join(", ")));
    }
    let fired_str = if fired.is_empty() { "none".to_string() } else { fired.join(", ") };
    let missed_str = if not_fired.is_empty() { "none".to_string() } else { not_fired.join(", ") };
    (None, 0.0, format!("{matched}/{evaluated} heuristics matched (fired: {fired_str}; missed: {missed_str})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwe_detectors() {
        assert!(cwe_buffer_overflow_shape(r#""A" * 100"#));
        assert!(cwe_buffer_overflow_shape(r#"b"\xde\xad\xbe\xef\xca\xfe\xba\xbe\xde\xad""#));
        assert!(!cwe_buffer_overflow_shape(r#"" " * 4"#));
        assert!(cwe_command_injection_shape(r#""; rm -rf /""#));
        assert!(cwe_command_injection_shape(r#""$(whoami)""#));
        assert!(cwe_sql_injection_shape("' OR 1=1"));
        assert!(cwe_sql_injection_shape("UNION SELECT x"));
        assert!(cwe_xss_shape("<script>"));
        assert!(cwe_xss_shape(r#"onerror="x""#));
        assert!(cwe_path_traversal_shape("../../etc"));
        assert!(cwe_path_traversal_shape("%2e%2e%2f"));
        assert!(cwe_null_deref_shape("f(NULL)"));
        assert!(cwe_null_deref_shape("x = None"));
        assert!(cwe_integer_overflow_shape("0xffffff"));
        assert!(cwe_integer_overflow_shape("2 ** 32"));
        assert!(cwe_integer_overflow_shape("INT_MAX"));
        assert!(cwe_integer_overflow_shape("SIZE_T_MAX"));
        assert!(!cwe_integer_overflow_shape("SIZE_MAX")); // SIZE_T? requires SIZE_ then _MAX -> double underscore
        assert!(!cwe_integer_overflow_shape("small"));
    }

    #[test]
    fn dispatch_and_overlap() {
        assert_eq!(cwe_shape(Some("CWE-120"), r#""A"*100"#), Some(true));
        assert_eq!(cwe_shape(Some("CWE-999"), "x"), None);
        assert_eq!(cwe_shape(None, "x"), None);
        assert!(file_overlap(Some("src/vuln.c"), "exploit for vuln.c"));
        assert!(!file_overlap(Some("vuln.c"), "vulncheck.cpp"));
        assert!(function_overlap(Some("check"), "call check()"));
        assert!(!function_overlap(Some("check"), "checkpoint"));
        assert!(compile_error_anchor(Some("vuln.c"), Some(&["vuln.c:3: error".to_string()])));
    }

    #[test]
    fn verdicts() {
        let off = initial_verdict(&[("file_overlap", Some(false)), ("function_overlap", Some(false)), ("cwe_shape", Some(false)), ("compile", None)]);
        assert_eq!(off, (Some("off_target"), 0.85, "no heuristics matched (3 evaluated); exploit appears to target a different bug".to_string()));

        let m3 = initial_verdict(&[("file_overlap", Some(true)), ("function_overlap", Some(true)), ("cwe_shape", Some(true)), ("compile", Some(false))]);
        assert_eq!(m3, (Some("matches"), 0.9, "3/4 heuristics matched: file_overlap, function_overlap, cwe_shape".to_string()));

        let all2 = initial_verdict(&[("file_overlap", Some(true)), ("function_overlap", Some(true)), ("cwe_shape", None), ("compile", None)]);
        assert_eq!(all2, (Some("matches"), 0.8, "all 2 evaluated heuristics matched: file_overlap, function_overlap".to_string()));

        let ambig = initial_verdict(&[("file_overlap", Some(true)), ("function_overlap", Some(false)), ("cwe_shape", None), ("compile", Some(false))]);
        assert_eq!(ambig, (None, 0.0, "1/3 heuristics matched (fired: file_overlap; missed: function_overlap, compile)".to_string()));

        let none = initial_verdict(&[("a", None), ("b", None)]);
        assert_eq!(none, (Some("uncertain"), 0.0, "no heuristic could evaluate (finding metadata absent)".to_string()));
    }
}
