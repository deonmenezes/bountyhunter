//! Log-output sanitisation for untrusted strings — Rust port of
//! `core/security/log_sanitisation.py`.
//!
//! `escape_nonprintable` replaces each non-printable character with `\xHH` so
//! attacker-influenced text (scanner output, filenames, SARIF metadata) can't
//! inject terminal escapes or corrupt log files. `has_nonprintable` is the
//! fail-closed predicate form.
//!
//! Non-printability matches Python's `str.isprintable()` exactly: a character is
//! non-printable when its Unicode general category is Other (Cc/Cf/Cs/Co/Cn) or
//! Separator (Zl/Zp/Zs) — except ASCII space (U+0020), which is printable.

use unicode_general_category::{get_general_category, GeneralCategory};

/// Mirror of Python's `str.isprintable()` for a single character.
fn is_printable(c: char) -> bool {
    // ASCII space is the one Separator that counts as printable.
    if c == ' ' {
        return true;
    }
    !matches!(
        get_general_category(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::Surrogate
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::SpaceSeparator
    )
}

fn is_structural_whitespace(c: char) -> bool {
    c == '\n' || c == '\t'
}

/// Return `s` with each non-printable character replaced by `\xHH`
/// (`escape_nonprintable`). When `preserve_newlines` is true, `\n` and `\t` are
/// kept as-is; all other non-printables are still escaped.
pub fn escape_nonprintable(s: &str, preserve_newlines: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let keep = is_printable(c) || (preserve_newlines && is_structural_whitespace(c));
        if keep {
            out.push(c);
        } else {
            out.push_str(&format!("\\x{:02x}", c as u32));
        }
    }
    out
}

/// Return true if any character of `s` is non-printable (`has_nonprintable`).
pub fn has_nonprintable(s: &str) -> bool {
    s.chars().any(|c| !is_printable(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_matches_python_isprintable() {
        assert_eq!(escape_nonprintable("hello world", false), "hello world");
        assert_eq!(escape_nonprintable("evil\x1b[2Jclear", false), "evil\\x1b[2Jclear");
        assert_eq!(escape_nonprintable("a\x00b\r\nc\td", false), "a\\x00b\\x0d\\x0ac\\x09d");
        // Zs (nbsp), Cf (zwsp), Zl (line separator) are non-printable.
        assert_eq!(escape_nonprintable("a\u{a0}b", false), "a\\xa0b");
        assert_eq!(escape_nonprintable("a\u{200b}b", false), "a\\x200bb");
        assert_eq!(escape_nonprintable("a\u{2028}b", false), "a\\x2028b");
        // Printables pass through: accented letters, emoji (So).
        assert_eq!(escape_nonprintable("café", false), "café");
        assert_eq!(escape_nonprintable("a\u{1f600}b", false), "a\u{1f600}b");
        // C1 control + DEL are non-printable.
        assert_eq!(escape_nonprintable("a\u{85}b", false), "a\\x85b");
        assert_eq!(escape_nonprintable("a\x7fb", false), "a\\x7fb");
    }

    #[test]
    fn preserve_newlines_keeps_tab_and_lf_only() {
        // \n and \t kept; \r still escaped.
        assert_eq!(escape_nonprintable("a\x00b\r\nc\td", true), "a\\x00b\\x0d\nc\td");
        assert_eq!(escape_nonprintable("evil\x1b[2Jclear", true), "evil\\x1b[2Jclear");
    }

    #[test]
    fn has_nonprintable_predicate() {
        assert!(!has_nonprintable("hello world"));
        assert!(!has_nonprintable("café"));
        assert!(!has_nonprintable("a\u{1f600}b"));
        assert!(has_nonprintable("evil\x1b"));
        assert!(has_nonprintable("a\u{a0}b"));
        assert!(has_nonprintable("a\u{200b}b"));
        assert!(has_nonprintable("a\x7fb"));
    }
}
