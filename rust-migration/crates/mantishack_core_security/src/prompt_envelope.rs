//! Prompt-envelope defences — Rust port of the pure, self-contained
//! `neutralize_tag_forgery` from `core/security/prompt_envelope.py`. The rest of
//! that module (bundle building, nonce generation, autofetch stripping) stays
//! Python.

use std::sync::OnceLock;

use regex::{Captures, Regex};

const ZWSP: &str = "\u{200b}";

fn envelope_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)",
            r"</?\s*untrusted[-_]",
            r"|</?\s*slots?\b",
            r"|</?\s*document(?:_content)?\b",
            r"|</?\s*untrusted_text\b",
            r"|\[/?\s*MARK_INPT\s*\]",
            r"|\bBEGIN_[A-Z_]+\b",
            r"|\bEND_[A-Z_]+\b",
        ))
        .unwrap()
    })
}

fn markdown_heading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^(#+)").unwrap())
}

fn escape_match(s: &str) -> String {
    // XML-style: leading `<` -> `&lt;`.
    if let Some(rest) = s.strip_prefix('<') {
        return format!("&lt;{rest}");
    }
    // Bracket-style: `[` -> `&#91;`, trailing `]` (if present) -> `&#93;`.
    if let Some(after) = s.strip_prefix('[') {
        let (inner, tail) = match after.strip_suffix(']') {
            Some(i) => (i, "&#93;"),
            None => (after, ""),
        };
        return format!("&#91;{inner}{tail}");
    }
    // Line-marker style (BEGIN_/END_): insert a ZWSP after the first `_`.
    let first = s.chars().next().map(|c| c.to_ascii_uppercase());
    if matches!(first, Some('B') | Some('E')) && s.contains('_') {
        let (head, tail) = s.split_once('_').unwrap();
        return format!("{head}_{ZWSP}{tail}");
    }
    s.to_string()
}

/// Escape sequences in untrusted content that could forge prompt structure
/// (`neutralize_tag_forgery`): neutralises envelope-tag forgery and
/// markdown-heading forgery without removing semantic content.
pub fn neutralize_tag_forgery(content: &str) -> String {
    let step1 = envelope_tag_re().replace_all(content, |caps: &Captures| escape_match(&caps[0]));
    markdown_heading_re().replace_all(&step1, |caps: &Captures| format!("\\{}", &caps[0])).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_forgery() {
        assert_eq!(neutralize_tag_forgery("</untrusted-text>"), "&lt;/untrusted-text>");
        assert_eq!(neutralize_tag_forgery("<slot foo>"), "&lt;slot foo>");
        assert_eq!(neutralize_tag_forgery("<document_content>"), "&lt;document_content>");
        assert_eq!(neutralize_tag_forgery("[MARK_INPT]"), "&#91;MARK_INPT&#93;");
        assert_eq!(neutralize_tag_forgery("[/MARK_INPT]"), "&#91;/MARK_INPT&#93;");
        assert_eq!(neutralize_tag_forgery("BEGIN_INPT rest"), format!("BEGIN_{ZWSP}INPT rest"));
        assert_eq!(neutralize_tag_forgery("END_X"), format!("END_{ZWSP}X"));
        assert_eq!(neutralize_tag_forgery("begin_foo"), format!("begin_{ZWSP}foo")); // IGNORECASE
    }

    #[test]
    fn heading_forgery_and_safe_content() {
        assert_eq!(neutralize_tag_forgery("## INJECTED\ntext"), "\\## INJECTED\ntext");
        assert_eq!(neutralize_tag_forgery("#!/bin/sh"), "\\#!/bin/sh");
        assert_eq!(neutralize_tag_forgery("line1\n## h2\n### h3"), "line1\n\\## h2\n\\### h3");
        // Normal `<` comparisons and inline text untouched.
        assert_eq!(neutralize_tag_forgery("a < b and c"), "a < b and c");
    }
}
