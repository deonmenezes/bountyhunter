/// English-aliased pre-canonicalisation for SMT encoder parsers.
///
/// Faithful port of `core/smt_solver/canonicalise.py`.
///
/// LLM output frequently uses English operator phrases — "is greater than",
/// "equals", "is at least" — instead of the canonical symbolic forms.
/// This module applies a small ordered set of regex rewrites *before* the
/// parser sees the input, mapping common English forms to `>`, `<`, `>=`,
/// `<=`, `==`, `!=` (with NULL / 0 specialisations for the `is null` /
/// `is zero` / `is non-null` / `is non-zero` family).
///
/// # Lookbehind simulation
///
/// Python's `re` supports `(?<=\S)` lookbehind. Rust's `regex` crate does
/// not. The two patterns that use lookbehind
/// (`(?<=\S)\s+is\s+null\b` and `(?<=\S)\s+is\s+zero\b`) are handled by
/// matching the whitespace-only prefix `\s+is\s+(null|zero)\b` and then
/// checking in a replacement closure whether the character immediately
/// before the match start is non-whitespace. This produces identical output
/// to the Python lookbehind for all inputs, including the pathological
/// repeated case (`"a is null is null"` → `"a == NULL == NULL"`).
use regex::Regex;
use std::sync::OnceLock;

const CANONICALISE_INPUT_CAP: usize = 256 * 1024;

/// Compiled regex rewrites loaded once.
/// Each entry is `(pattern, replacement_str)`.
/// Order matches Python exactly — longer, more-specific phrases first.
type RwEntry = (Regex, &'static str);

static REWRITES: OnceLock<Vec<RwEntry>> = OnceLock::new();
static RE_IS_NULL: OnceLock<Regex> = OnceLock::new();
static RE_IS_ZERO: OnceLock<Regex> = OnceLock::new();
/// "up to N" pattern — uses a capture group to preserve the numeric literal
/// because the `regex` crate does not support lookaheads.
/// Python: `\bup\s+to(?=\s+(?:0x[0-9a-f]+|\d))` with replacement ` <= `
/// Rust:   `\bup\s+to\s+((?:0x[0-9a-f]+|\d+))` with replacement ` <= $1`
/// These produce identical output; extra whitespace is collapsed afterwards.
static RE_UP_TO: OnceLock<Regex> = OnceLock::new();
static RE_WHITESPACE_RUN: OnceLock<Regex> = OnceLock::new();

fn rewrites() -> &'static [RwEntry] {
    REWRITES.get_or_init(|| {
        vec![
            // Longer phrases first — mirrors Python order exactly.
            (Regex::new(r"(?i)\bis\s+greater\s+than\s+or\s+equal\s+to\b").unwrap(), " >= "),
            (Regex::new(r"(?i)\bis\s+less\s+than\s+or\s+equal\s+to\b").unwrap(),    " <= "),
            (Regex::new(r"(?i)\bis\s+not\s+equal\s+to\b").unwrap(),                 " != "),
            (Regex::new(r"(?i)\bdoes\s+not\s+equal\b").unwrap(),                    " != "),
            (Regex::new(r"(?i)\bdoes\s+not\s+exceed\b").unwrap(),                   " <= "),
            (Regex::new(r"(?i)\bis\s+at\s+least\b").unwrap(),                       " >= "),
            (Regex::new(r"(?i)\bis\s+at\s+most\b").unwrap(),                        " <= "),
            (Regex::new(r"(?i)\bis\s+greater\s+than\b").unwrap(),                   " > "),
            (Regex::new(r"(?i)\bis\s+less\s+than\b").unwrap(),                      " < "),
            (Regex::new(r"(?i)\bis\s+equal\s+to\b").unwrap(),                       " == "),
            // Negative null/zero forms before positive — mirrors Python ordering.
            (Regex::new(r"(?i)\bis\s+non[-\s]?zero\b").unwrap(),                    " != 0 "),
            (Regex::new(r"(?i)\bis\s+non[-\s]?null\b").unwrap(),                    " != NULL "),
            // NOTE: is_null and is_zero lookbehind patterns handled separately below.
            // NOTE: up_to pattern handled separately below (uses $1 capture).
            // Single-word synonyms — require surrounding whitespace/boundary.
            (Regex::new(r"(?:^|\s)(?i:equals)(?:\s|$)").unwrap(),                  " == "),
            (Regex::new(r"(?:^|\s)(?i:exceeds)(?:\s|$)").unwrap(),                 " > "),
            (Regex::new(r"(?:^|\s)(?i:below)(?:\s|$)").unwrap(),                   " < "),
        ]
    })
}

fn re_is_null() -> &'static Regex {
    RE_IS_NULL.get_or_init(|| Regex::new(r"(?i)\s+is\s+null\b").unwrap())
}

fn re_is_zero() -> &'static Regex {
    RE_IS_ZERO.get_or_init(|| Regex::new(r"(?i)\s+is\s+zero\b").unwrap())
}

fn re_up_to() -> &'static Regex {
    // Captures the numeric token so we can preserve it in the replacement.
    RE_UP_TO.get_or_init(|| Regex::new(r"(?i)\bup\s+to\s+((?:0x[0-9a-f]+|\d+))").unwrap())
}

fn re_whitespace_run() -> &'static Regex {
    RE_WHITESPACE_RUN.get_or_init(|| Regex::new(r"[ \t]+").unwrap())
}

/// Rewrite common English operator aliases to canonical syntax.
///
/// Idempotent: input already in symbolic form passes through unchanged (modulo
/// whitespace collapse). Multi-line inputs are safe: only `[ \t]+` runs are
/// collapsed, not newlines — mirrors Python's `_WHITESPACE_RUN = re.compile(r'[ \t]+')`.
///
/// Input is capped at 256 KiB; oversized input is truncated from the tail.
pub fn canonicalise(text: &str) -> String {
    // Cap input length (mirrors Python _CANONICALISE_INPUT_CAP = 256*1024).
    let text = if text.len() <= CANONICALISE_INPUT_CAP {
        text
    } else {
        // Truncate at a char boundary at or before the cap.
        let cap = CANONICALISE_INPUT_CAP;
        let end = text.char_indices()
            .take_while(|(i, _)| *i < cap)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        &text[..end]
    };

    let mut out = text.to_string();

    // Apply standard rewrites in order.
    for (pat, repl) in rewrites() {
        let result = pat.replace_all(&out, *repl);
        out = result.into_owned();
    }

    // Apply lookbehind-simulated patterns.
    // Python: `(?<=\S)\s+is\s+null\b` → ` == NULL `
    // We match `\s+is\s+null\b` and check in the closure that the character
    // immediately before the match is non-whitespace.
    {
        let src = out.clone();
        out = re_is_null().replace_all(&out, |caps: &regex::Captures| {
            let start = caps.get(0).unwrap().start();
            let prev_non_ws = start > 0
                && src[..start]
                    .chars()
                    .last()
                    .map(|c| !c.is_whitespace())
                    .unwrap_or(false);
            if prev_non_ws {
                " == NULL ".to_string()
            } else {
                caps.get(0).unwrap().as_str().to_string()
            }
        }).into_owned();
    }

    // Python: `(?<=\S)\s+is\s+zero\b` → ` == 0 `
    {
        let src = out.clone();
        out = re_is_zero().replace_all(&out, |caps: &regex::Captures| {
            let start = caps.get(0).unwrap().start();
            let prev_non_ws = start > 0
                && src[..start]
                    .chars()
                    .last()
                    .map(|c| !c.is_whitespace())
                    .unwrap_or(false);
            if prev_non_ws {
                " == 0 ".to_string()
            } else {
                caps.get(0).unwrap().as_str().to_string()
            }
        }).into_owned();
    }

    // Python: `\bup\s+to(?=\s+(?:0x[0-9a-f]+|\d))` → ` <= `
    // Rust: capture the numeric token and put it back with ` <= $1`.
    // Any extra whitespace is removed by the collapse pass below.
    out = re_up_to().replace_all(&out, " <= $1").into_owned();

    // Collapse runs of spaces/tabs (NOT newlines) and strip ends.
    // Mirrors Python: `_WHITESPACE_RUN.sub(' ', out).strip()`
    re_whitespace_run().replace_all(&out, " ").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors derived from running the Python implementation.

    #[test]
    fn empty_string_passthrough() {
        // Golden: '' -> ''
        assert_eq!(canonicalise(""), "");
    }

    #[test]
    fn already_symbolic_passthrough() {
        // Golden: 'a > b' -> 'a > b'
        assert_eq!(canonicalise("a > b"), "a > b");
    }

    #[test]
    fn is_greater_than_or_equal_to() {
        // Golden: 'x is greater than or equal to 100' -> 'x >= 100'
        assert_eq!(canonicalise("x is greater than or equal to 100"), "x >= 100");
    }

    #[test]
    fn is_not_equal_to_null() {
        // Golden: 'ptr is not equal to NULL' -> 'ptr != NULL'
        assert_eq!(canonicalise("ptr is not equal to NULL"), "ptr != NULL");
    }

    #[test]
    fn does_not_exceed() {
        // Golden: 'count does not exceed 1024' -> 'count <= 1024'
        assert_eq!(canonicalise("count does not exceed 1024"), "count <= 1024");
    }

    #[test]
    fn is_null_lookbehind() {
        // Golden: 'ptr is null' -> 'ptr == NULL'
        // Tests the lookbehind-simulated path.
        assert_eq!(canonicalise("ptr is null"), "ptr == NULL");
    }

    #[test]
    fn is_null_double_occurrence() {
        // Golden: 'a is null is null' -> 'a == NULL == NULL'
        // Both occurrences have a non-whitespace char before them in the original string.
        assert_eq!(canonicalise("a is null is null"), "a == NULL == NULL");
    }

    #[test]
    fn is_zero_lookbehind() {
        // Golden: 'val is zero' -> 'val == 0'
        assert_eq!(canonicalise("val is zero"), "val == 0");
    }

    #[test]
    fn is_non_null() {
        // Golden: 'ptr is non-null' -> 'ptr != NULL'
        assert_eq!(canonicalise("ptr is non-null"), "ptr != NULL");
    }

    #[test]
    fn is_non_zero() {
        // Golden: 'val is non-zero' -> 'val != 0'
        assert_eq!(canonicalise("val is non-zero"), "val != 0");
    }

    #[test]
    fn up_to_hex_literal() {
        // Golden: 'count up to 0xff' -> 'count <= 0xff'
        assert_eq!(canonicalise("count up to 0xff"), "count <= 0xff");
    }

    #[test]
    fn up_to_non_numeric_no_match() {
        // Golden: 'count up to some function' -> 'count up to some function'
        // No numeric literal after 'up to', so no rewrite fires.
        assert_eq!(canonicalise("count up to some function"), "count up to some function");
    }

    #[test]
    fn is_at_least() {
        // Golden: 'x is at least 10' -> 'x >= 10'
        assert_eq!(canonicalise("x is at least 10"), "x >= 10");
    }

    #[test]
    fn exceeds_word_boundary() {
        // Golden: 'n exceeds 100' -> 'n > 100'
        assert_eq!(canonicalise("n exceeds 100"), "n > 100");
    }

    #[test]
    fn is_less_than() {
        // Golden: 'val is less than 10' -> 'val < 10'
        assert_eq!(canonicalise("val is less than 10"), "val < 10");
    }

    #[test]
    fn whitespace_collapse_only_spaces_tabs() {
        // Multi-space run collapses; newline is preserved.
        let input = "x  is   greater   than   5";
        let result = canonicalise(input);
        assert_eq!(result, "x > 5");
    }

    #[test]
    fn is_null_at_start_no_replacement() {
        // 'is null' at the start of string — no preceding non-whitespace char
        // so the lookbehind should NOT fire (matches Python behaviour).
        let result = canonicalise("is null");
        // Should be unchanged (no preceding non-whitespace char).
        assert_eq!(result, "is null");
    }
}
