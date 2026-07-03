//! Pure, deterministic helpers from `packages/checker_synthesis/synthesise.py`.
//!
//! Ported: input validation (`validate_seed_path`, `validate_rule_body`),
//! `slugify`, `make_rule_id`, `rule_extension`, `is_seed_match`, `fp_rate`, and
//! the numeric constants. Everything else in synthesise.py stays Python by
//! design: the `LLMCallable` protocol, `_propose_rule` / `_positive_control` /
//! `_triage`, the semgrep/coccinelle runner adapters, the atomic `_write_rule`
//! filesystem write, and the `synthesise_and_run` / `synthesise_with_refinement`
//! orchestration loops (LLM-call and subprocess-bound, non-deterministic).

use regex::Regex;

use crate::models::{CheckerSynthesisResult, Match, SeedBug};

/// Hard upper bound on rule body size (UTF-8 bytes).
pub const RULE_BODY_MAX_BYTES: usize = 32_768;
/// Per-line ceiling on the rule body (code points).
pub const RULE_BODY_MAX_LINE: usize = 4_096;
/// Maximum `seed.snippet` size plumbed into the LLM prompt (UTF-8 bytes).
pub const SEED_SNIPPET_MAX_BYTES: usize = 8_192;
/// Match count above which the codebase scan flags "rule too loose".
pub const RULE_TOO_LOOSE_THRESHOLD: i64 = 200;

/// Python `repr()` of a string for the realistic case (no newline/null — those
/// are rejected earlier). Single quotes unless the string has `'` but not `"`.
fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Final path component (mirrors `pathlib.PurePosixPath(p).name`).
fn py_name(p: &str) -> &str {
    let trimmed = p.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// Reject seed file paths that could escape `repo_root` or are absolute.
/// Returns an error string on rejection, or `None` if OK.
pub fn validate_seed_path(file_path: &str) -> Option<String> {
    if file_path.is_empty() {
        return Some("seed.file must be non-empty".to_string());
    }
    if file_path.contains(['\n', '\r', '\x00']) {
        return Some("seed.file must not contain newline / null characters".to_string());
    }
    if file_path.starts_with('/') {
        return Some(format!("seed.file must be relative: {}", py_repr(file_path)));
    }
    if file_path.split('/').any(|part| part == "..") {
        return Some(format!("seed.file may not contain '..' segments: {}", py_repr(file_path)));
    }
    None
}

/// Reject rule bodies with control chars or oversized lines.
pub fn validate_rule_body(body: &str) -> Option<String> {
    if body.contains('\x00') {
        return Some("rule body contains null byte".to_string());
    }
    for (idx, line) in body.split('\n').enumerate() {
        let n = line.chars().count();
        if n > RULE_BODY_MAX_LINE {
            return Some(format!(
                "rule body line {} exceeds {} chars ({})",
                idx + 1,
                RULE_BODY_MAX_LINE,
                n
            ));
        }
    }
    None
}

/// File-safe slug for rule_id construction.
pub fn slugify(value: &str) -> String {
    let re = Regex::new(r"[^A-Za-z0-9_.-]+").unwrap();
    let subbed = re.replace_all(value, "_");
    let stripped = subbed.trim_matches(|c| c == '_' || c == '.');
    if stripped.is_empty() {
        "x".to_string()
    } else {
        stripped.to_string()
    }
}

/// Stable rule_id used for filenames + log lines.
pub fn make_rule_id(seed: &SeedBug, attempt: i64) -> String {
    format!(
        "{}.{}.{}.{}",
        slugify(&seed.file),
        slugify(&seed.function),
        slugify(&seed.cwe),
        attempt
    )
}

/// Rule filename extension for an engine.
pub fn rule_extension(engine: &str) -> &'static str {
    if engine == "semgrep" {
        ".yml"
    } else {
        ".cocci"
    }
}

/// Identify a match that IS the seed bug (so it can be dropped from variants).
pub fn is_seed_match(seed: &SeedBug, m: &Match) -> bool {
    if py_name(&m.file) != py_name(&seed.file) {
        return false;
    }
    seed.line_start <= m.line && m.line <= seed.line_end
}

/// Fraction of triaged matches classified false-positive; `None` when it can't
/// be computed (no triage, or everything skipped — skipped is excluded).
pub fn fp_rate(result: &CheckerSynthesisResult) -> Option<f64> {
    let triaged: Vec<&_> = result.triage.iter().filter(|t| t.status != "skipped").collect();
    if triaged.is_empty() {
        return None;
    }
    let fps = triaged.iter().filter(|t| t.status == "false_positive").count();
    Some(fps as f64 / triaged.len() as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::MatchTriage;

    fn seed() -> SeedBug {
        SeedBug::new("src/foo.py".into(), "login".into(), 10, 20, "CWE-89".into(), "r".into(), None)
    }

    #[test]
    fn validate_seed_path_cases() {
        assert_eq!(validate_seed_path(""), Some("seed.file must be non-empty".into()));
        assert_eq!(
            validate_seed_path("a\nb"),
            Some("seed.file must not contain newline / null characters".into())
        );
        assert_eq!(
            validate_seed_path("a\x00b"),
            Some("seed.file must not contain newline / null characters".into())
        );
        assert_eq!(
            validate_seed_path("/etc/passwd"),
            Some("seed.file must be relative: '/etc/passwd'".into())
        );
        assert_eq!(
            validate_seed_path("a/../b"),
            Some("seed.file may not contain '..' segments: 'a/../b'".into())
        );
        assert_eq!(validate_seed_path("src/ok.py"), None);
        // "..b" is a filename, not a parent ref.
        assert_eq!(validate_seed_path("a/..b"), None);
    }

    #[test]
    fn validate_rule_body_cases() {
        assert_eq!(validate_rule_body("null\x00byte"), Some("rule body contains null byte".into()));
        assert_eq!(validate_rule_body("ok\nfine"), None);
        let long = "x".repeat(RULE_BODY_MAX_LINE + 1);
        assert_eq!(
            validate_rule_body(&format!("ok\n{long}")),
            Some(format!("rule body line 2 exceeds 4096 chars ({})", RULE_BODY_MAX_LINE + 1))
        );
        // exactly at the cap is fine
        assert_eq!(validate_rule_body(&"y".repeat(RULE_BODY_MAX_LINE)), None);
    }

    #[test]
    fn slugify_cases() {
        assert_eq!(slugify("src/foo.py"), "src_foo.py");
        assert_eq!(slugify("CWE-89"), "CWE-89");
        assert_eq!(slugify("login"), "login");
        assert_eq!(slugify("__weird!!__"), "weird");
        assert_eq!(slugify("!!!"), "x");
        assert_eq!(slugify(""), "x");
        assert_eq!(slugify("...a..."), "a");
    }

    #[test]
    fn make_rule_id_shape() {
        assert_eq!(make_rule_id(&seed(), 0), "src_foo.py.login.CWE-89.0");
        assert_eq!(make_rule_id(&seed(), 2), "src_foo.py.login.CWE-89.2");
    }

    #[test]
    fn rule_extension_cases() {
        assert_eq!(rule_extension("semgrep"), ".yml");
        assert_eq!(rule_extension("coccinelle"), ".cocci");
        assert_eq!(rule_extension("anything-else"), ".cocci");
    }

    #[test]
    fn is_seed_match_cases() {
        let s = seed();
        assert!(is_seed_match(&s, &Match::new("other/foo.py".into(), 15, None, None))); // same basename, in range
        assert!(!is_seed_match(&s, &Match::new("src/foo.py".into(), 21, None, None))); // out of range
        assert!(!is_seed_match(&s, &Match::new("src/bar.py".into(), 15, None, None))); // different basename
        assert!(is_seed_match(&s, &Match::new("src/foo.py".into(), 10, None, None))); // boundary start
        assert!(is_seed_match(&s, &Match::new("src/foo.py".into(), 20, None, None))); // boundary end
    }

    #[test]
    fn fp_rate_cases() {
        let mut r = CheckerSynthesisResult::new(seed());
        assert_eq!(fp_rate(&r), None); // no triage
        let m = || Match::new("a.py".into(), 1, None, None);
        r.triage = vec![
            MatchTriage::new(m(), "false_positive".into(), None),
            MatchTriage::new(m(), "variant".into(), None),
            MatchTriage::new(m(), "skipped".into(), None), // excluded from denominator
        ];
        assert_eq!(fp_rate(&r), Some(0.5));
        // everything skipped → None
        r.triage = vec![MatchTriage::new(m(), "skipped".into(), None)];
        assert_eq!(fp_rate(&r), None);
    }
}
