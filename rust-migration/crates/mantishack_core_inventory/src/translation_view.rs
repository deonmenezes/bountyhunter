//! TranslationView — the parser's view of a source file. Faithful Rust port
//! of `core/inventory/translation_view.py`.
//!
//! C/C++ extraction runs on *unpreprocessed* text (tree-sitter doesn't run the
//! C preprocessor), so `#if 0` arms and both sides of every `#ifdef` reach the
//! parser as if live. This module is the seam: it blanks statically-dead
//! preprocessor arms in-memory (never touching the file) so increasingly
//! faithful preprocessing can slot in behind a stable interface.
//!
//! Fidelity ladder: 0 = raw text (non-C/C++, isolation mode); 1 = literal-only
//! dead arms blanked (`#if 0` / `#elif 0` / `#else` of `#if 1`); 2 =
//! config-aware via a [`MacroConfig`]; 3 = real `cpp` (deferred).
//!
//! `line_map` is identity at fidelity < 3 because blanking replaces dead-arm
//! characters with spaces and never adds or removes a newline.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;

/// Build macro configuration consulted at fidelity 2. Duck-typed in the Python
/// original (`macros.is_defined` / `macros.value_of`); a trait here.
pub trait MacroConfig {
    /// `Some(true)` = explicitly defined, `Some(false)` = explicitly undefined,
    /// `None` = unknown (absent from the config — may be defined in a header).
    fn is_defined(&self, name: &str) -> Option<bool>;
    /// The value a known-defined symbol expands to, if any.
    fn value_of(&self, name: &str) -> Option<String>;
}

/// Languages whose extraction goes through the C-preprocessor-aware path.
pub const C_FAMILY: &[&str] = &["c", "cpp"];

fn pp_directive_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$").unwrap())
}

fn defined_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(!\s*)?defined\s*\(\s*(\w+)\s*\)$").unwrap())
}

fn defined_bare_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(!\s*)?defined\s+(\w+)$").unwrap())
}

fn ident_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(\w+)$").unwrap())
}

fn block_comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"/\*.*?\*/").unwrap())
}

fn line_comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"//.*").unwrap())
}

fn strip_pp_comments(rest: &str) -> String {
    let no_block = block_comment_re().replace_all(rest, "");
    line_comment_re().replace_all(&no_block, "").trim().to_string()
}

/// Parse a bare integer literal (decimal / 0x-hex / 0o / 0b, optional
/// surrounding parens and `u`/`U`/`l`/`L` suffix). `None` for anything
/// non-trivial — matching Python's `int(t, 0)` (which rejects leading-zero
/// decimals like `012`).
fn eval_int_literal(s: &str) -> Option<i64> {
    let mut t = s.trim();
    while t.starts_with('(') && t.ends_with(')') && t.len() >= 2 {
        t = t[1..t.len() - 1].trim();
    }
    let t = t.trim_end_matches(['u', 'U', 'l', 'L']);
    if t.is_empty() {
        return None;
    }
    let (neg, body) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    if body.is_empty() {
        return None;
    }
    let val = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()?
    } else if let Some(o) = body.strip_prefix("0o").or_else(|| body.strip_prefix("0O")) {
        i64::from_str_radix(o, 8).ok()?
    } else if let Some(b) = body.strip_prefix("0b").or_else(|| body.strip_prefix("0B")) {
        i64::from_str_radix(b, 2).ok()?
    } else {
        // Decimal: `int(_, 0)` rejects a leading zero unless the value is "0".
        if body.len() > 1 && body.starts_with('0') {
            return None;
        }
        if !body.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        body.parse::<i64>().ok()?
    };
    Some(if neg { -val } else { val })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cond {
    False,
    True,
    Unknown,
}

/// Classify an `#if`/`#ifdef`/`#ifndef`/`#elif` controlling expression as
/// false / true / unknown. Without a config only literal `0`/`1` decide;
/// with one, single-term `#ifdef`/`defined(X)`/`#if X` forms whose symbols
/// are explicitly known resolve too. Compound expressions stay unknown.
fn pp_cond(kind: &str, rest: &str, macros: Option<&dyn MacroConfig>) -> Cond {
    if kind == "ifdef" || kind == "ifndef" {
        let stripped = strip_pp_comments(rest);
        let m = ident_re().captures(&stripped);
        match (m, macros) {
            (Some(caps), Some(cfg)) => match cfg.is_defined(&caps[1]) {
                None => Cond::Unknown,
                Some(d) => {
                    let defined_true = if kind == "ifdef" { d } else { !d };
                    if defined_true {
                        Cond::True
                    } else {
                        Cond::False
                    }
                }
            },
            _ => Cond::Unknown,
        }
    } else {
        let r = strip_pp_comments(rest);
        if r == "0" || r == "(0)" || r == "00" {
            return Cond::False;
        }
        if r == "1" || r == "(1)" {
            return Cond::True;
        }
        let Some(cfg) = macros else {
            return Cond::Unknown;
        };

        // defined(X) / !defined(X) / defined X
        if let Some(dm) = defined_re().captures(&r).or_else(|| defined_bare_re().captures(&r)) {
            return match cfg.is_defined(&dm[2]) {
                None => Cond::Unknown,
                Some(d) => {
                    let res = if dm.get(1).is_some() { !d } else { d };
                    if res {
                        Cond::True
                    } else {
                        Cond::False
                    }
                }
            };
        }

        // bare single identifier: #if MACRO
        if let Some(im) = ident_re().captures(&r) {
            let name = &im[1];
            if let Some(val) = cfg.value_of(name) {
                return match eval_int_literal(&val) {
                    None => Cond::Unknown,
                    Some(iv) => {
                        if iv != 0 {
                            Cond::True
                        } else {
                            Cond::False
                        }
                    }
                };
            }
            // Known-undefined identifier → 0 in #if → false; absent stays unknown.
            if cfg.is_defined(name) == Some(false) {
                return Cond::False;
            }
        }
        Cond::Unknown
    }
}

#[derive(Clone, Copy)]
struct Frame {
    parent_dead: bool,
    taken: bool,
    arm_dead: bool,
    effective_dead: bool,
}

/// Inclusive 1-indexed line ranges of statically-dead preprocessor arms.
/// Nesting-aware (anything inside a dead arm is dead). Directive lines
/// themselves are never reported — only the guarded content.
pub fn detect_preprocessor_dead_ranges(
    content: &str,
    macros: Option<&dyn MacroConfig>,
) -> Vec<(usize, usize)> {
    let mut stack: Vec<Frame> = Vec::new();
    let mut dead: BTreeSet<usize> = BTreeSet::new();

    for (idx, line) in content.split('\n').enumerate() {
        let i = idx + 1;
        let Some(caps) = pp_directive_re().captures(line) else {
            if stack.last().is_some_and(|f| f.effective_dead) {
                dead.insert(i);
            }
            continue;
        };
        let kind = caps.get(1).unwrap().as_str();
        let rest = caps.get(2).unwrap().as_str();
        let parent_dead = stack.last().map(|f| f.effective_dead).unwrap_or(false);

        match kind {
            "if" | "ifdef" | "ifndef" => {
                let lit = pp_cond(kind, rest, macros);
                let arm_dead = lit == Cond::False;
                stack.push(Frame {
                    parent_dead,
                    taken: lit == Cond::True,
                    arm_dead,
                    effective_dead: parent_dead || arm_dead,
                });
            }
            "elif" if !stack.is_empty() => {
                let lit = pp_cond("elif", rest, macros);
                let f = stack.last_mut().unwrap();
                if f.taken || lit == Cond::False {
                    f.arm_dead = true;
                } else if lit == Cond::True {
                    f.arm_dead = false;
                    f.taken = true;
                } else {
                    f.arm_dead = false;
                }
                f.effective_dead = f.parent_dead || f.arm_dead;
            }
            "else" if !stack.is_empty() => {
                let f = stack.last_mut().unwrap();
                f.arm_dead = f.taken; // dead iff a true arm was already taken
                f.effective_dead = f.parent_dead || f.arm_dead;
            }
            "endif" if !stack.is_empty() => {
                stack.pop();
            }
            _ => {}
        }
    }

    // Coalesce consecutive dead line numbers into inclusive ranges.
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut run: Option<(usize, usize)> = None;
    for &ln in &dead {
        match run {
            Some((lo, hi)) if ln == hi + 1 => run = Some((lo, ln)),
            Some((lo, hi)) => {
                ranges.push((lo, hi));
                run = Some((ln, ln));
            }
            None => run = Some((ln, ln)),
        }
    }
    if let Some(r) = run {
        ranges.push(r);
    }
    ranges
}

fn func_macro_def_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^[ \t]*#[ \t]*define[ \t]+(\w+)[ \t]*\(([^)]*)\)(.*)$").unwrap())
}

fn call_in_body_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([A-Za-z_]\w*)[ \t]*\(").unwrap())
}

const C_NON_CALL_KW: &[&str] = &[
    "if", "while", "for", "switch", "return", "sizeof", "defined", "do", "else", "case",
    "alignof", "_Alignof", "static_assert", "_Static_assert", "catch",
];

/// Blank string / char literals and comments in a logical macro body so
/// call-shaped text inside them isn't mistaken for a routed call. `//` ends
/// the logical line.
fn strip_c_literals_comments(s: &str) -> String {
    let b = s.as_bytes();
    let n = b.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i = 0usize;
    while i < n {
        let c = b[i];
        if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            match find_sub(b, i + 2, b"*/") {
                Some(j) => i = j + 2,
                None => i = n,
            }
            continue;
        }
        if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
            break;
        }
        if c == b'"' || c == b'\'' {
            let q = c;
            i += 1;
            while i < n {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

fn find_sub(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from > haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

/// Function names invoked inside function-like macro bodies (C/C++ only) —
/// the resolver treats these as UNCERTAIN rather than NOT_CALLED so a
/// function reachable only via `#define CALL_F() f()` isn't a false negative.
pub fn detect_macro_call_targets(content: &str) -> BTreeSet<String> {
    let mut targets: BTreeSet<String> = BTreeSet::new();
    if content.is_empty() || !content.contains("define") {
        return targets;
    }
    let joined = content.replace("\\\n", " "); // fold line-continuations
    for caps in func_macro_def_re().captures_iter(&joined) {
        let macro_name = caps.get(1).unwrap().as_str();
        let body = strip_c_literals_comments(caps.get(3).unwrap().as_str());
        for c in call_in_body_re().captures_iter(&body) {
            let name = c.get(1).unwrap().as_str();
            if name != macro_name && !C_NON_CALL_KW.contains(&name) {
                targets.insert(name.to_string());
            }
        }
    }
    targets
}

fn blank_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[^\n]").unwrap())
}

/// Replace the body of each dead range with same-length spaces, preserving
/// newlines so byte/line offsets — and the identity line_map — stay stable.
fn blank_ranges(content: &str, ranges: &[(usize, usize)]) -> String {
    if ranges.is_empty() {
        return content.to_string();
    }
    let mut dead: BTreeSet<usize> = BTreeSet::new();
    for &(lo, hi) in ranges {
        for ln in lo..=hi {
            dead.insert(ln);
        }
    }
    let blank = blank_line_re();
    content
        .split('\n')
        .enumerate()
        .map(|(idx, line)| {
            if dead.contains(&(idx + 1)) {
                blank.replace_all(line, " ").into_owned()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Maps a 1-indexed `parse_text` line back to a 1-indexed source line. Empty
/// `entries` ⇒ identity (the case at fidelity < 3).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LineMap {
    pub entries: Vec<(usize, usize)>,
}

impl LineMap {
    pub fn identity() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn to_source(&self, parse_line: usize) -> usize {
        if self.entries.is_empty() {
            return parse_line;
        }
        let mut src = parse_line;
        for &(p_line, s_line) in &self.entries {
            if p_line <= parse_line {
                src = s_line + (parse_line - p_line);
            } else {
                break;
            }
        }
        src
    }
}

/// What the parser sees, plus provenance for the reachability layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslationView {
    pub parse_text: String,
    pub line_map: LineMap,
    pub fidelity: u8,
    pub masking_flags: BTreeSet<String>,
}

/// Return the parser's view of `content`. Non-C/C++ (or isolation mode) →
/// identity view (fidelity 0). C/C++ → dead preprocessor arms blanked
/// in-memory: literal-only (fidelity 1) without `macros`, config-aware
/// (fidelity 2) with one. No on-disk mutation; line_map stays identity.
pub fn preprocess_view(
    language: &str,
    content: &str,
    allow_unreachable: bool,
    macros: Option<&dyn MacroConfig>,
) -> TranslationView {
    if !C_FAMILY.contains(&language) || allow_unreachable {
        return TranslationView {
            parse_text: content.to_string(),
            line_map: LineMap::identity(),
            fidelity: 0,
            masking_flags: BTreeSet::new(),
        };
    }
    let dead = detect_preprocessor_dead_ranges(content, macros);
    let parse_text = blank_ranges(content, &dead);
    TranslationView {
        parse_text,
        line_map: LineMap::identity(),
        fidelity: if macros.is_some() { 2 } else { 1 },
        masking_flags: BTreeSet::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Test double for [`MacroConfig`] backed by two maps.
    struct StubMacros {
        defined: HashMap<String, bool>,
        values: HashMap<String, String>,
    }
    impl MacroConfig for StubMacros {
        fn is_defined(&self, name: &str) -> Option<bool> {
            self.defined.get(name).copied()
        }
        fn value_of(&self, name: &str) -> Option<String> {
            self.values.get(name).cloned()
        }
    }

    fn ranges(content: &str) -> Vec<(usize, usize)> {
        detect_preprocessor_dead_ranges(content, None)
    }

    // --- literal-only dead ranges (fidelity 1) ----------------------------

    #[test]
    fn if_zero_body_is_dead() {
        let src = "a\n#if 0\ndead1\ndead2\n#endif\nb\n";
        assert_eq!(ranges(src), vec![(3, 4)]);
    }

    #[test]
    fn if_one_keeps_body_else_is_dead() {
        let src = "#if 1\nlive\n#else\ndead\n#endif\n";
        assert_eq!(ranges(src), vec![(4, 4)]);
    }

    #[test]
    fn elif_zero_is_dead() {
        let src = "#if COND\nx\n#elif 0\ndead\n#endif\n";
        assert_eq!(ranges(src), vec![(4, 4)]);
    }

    #[test]
    fn ifdef_without_config_is_unknown() {
        // No macros: #ifdef stays live (unknown), nothing blanked.
        assert_eq!(ranges("#ifdef FOO\nbody\n#endif\n"), Vec::<(usize, usize)>::new());
    }

    #[test]
    fn nested_dead_arm_everything_inside_dead() {
        let src = "#if 0\nouter\n#if 1\ninner_would_be_live\n#endif\nmore\n#endif\n";
        // Lines 2,4,6 are content; 3 and 5 are directives (never reported).
        assert_eq!(ranges(src), vec![(2, 2), (4, 4), (6, 6)]);
    }

    #[test]
    fn directive_lines_never_reported() {
        let src = "#if 0\nx\n#endif\n";
        assert_eq!(ranges(src), vec![(2, 2)]);
    }

    // --- config-aware (fidelity 2) ----------------------------------------

    #[test]
    fn ifdef_known_undefined_is_dead() {
        let macros = StubMacros {
            defined: HashMap::from([("FOO".to_string(), false)]),
            values: HashMap::new(),
        };
        let src = "#ifdef FOO\ndead\n#endif\n";
        assert_eq!(detect_preprocessor_dead_ranges(src, Some(&macros)), vec![(2, 2)]);
    }

    #[test]
    fn ifndef_known_defined_is_dead() {
        let macros = StubMacros {
            defined: HashMap::from([("FOO".to_string(), true)]),
            values: HashMap::new(),
        };
        let src = "#ifndef FOO\ndead\n#endif\n";
        assert_eq!(detect_preprocessor_dead_ranges(src, Some(&macros)), vec![(2, 2)]);
    }

    #[test]
    fn if_macro_value_zero_is_dead() {
        let macros = StubMacros {
            defined: HashMap::from([("N".to_string(), true)]),
            values: HashMap::from([("N".to_string(), "0".to_string())]),
        };
        assert_eq!(detect_preprocessor_dead_ranges("#if N\ndead\n#endif\n", Some(&macros)), vec![(2, 2)]);
    }

    #[test]
    fn if_defined_absent_stays_unknown() {
        // Symbol absent from config → unknown → not blanked (no over-fire).
        let macros = StubMacros { defined: HashMap::new(), values: HashMap::new() };
        assert_eq!(detect_preprocessor_dead_ranges("#if defined(X)\nbody\n#endif\n", Some(&macros)), Vec::<(usize, usize)>::new());
    }

    // --- macro call targets ----------------------------------------------

    #[test]
    fn macro_call_target_extracted() {
        let src = "#define CALL_F() f()\n";
        let t = detect_macro_call_targets(src);
        assert!(t.contains("f"));
        assert!(!t.contains("CALL_F"));
    }

    #[test]
    fn macro_body_string_call_not_extracted() {
        let src = "#define LOG() printf(\"foo()\")\n";
        let t = detect_macro_call_targets(src);
        assert!(t.contains("printf"));
        assert!(!t.contains("foo"));
    }

    #[test]
    fn macro_control_flow_keyword_not_a_call() {
        let src = "#define GUARD(x) if (x) bar()\n";
        let t = detect_macro_call_targets(src);
        assert!(t.contains("bar"));
        assert!(!t.contains("if"));
    }

    #[test]
    fn no_define_returns_empty() {
        assert!(detect_macro_call_targets("int main() { return 0; }\n").is_empty());
    }

    // --- eval_int_literal -------------------------------------------------

    #[test]
    fn int_literal_forms() {
        assert_eq!(eval_int_literal("0"), Some(0));
        assert_eq!(eval_int_literal("42"), Some(42));
        assert_eq!(eval_int_literal("0x1F"), Some(31));
        assert_eq!(eval_int_literal("(7)"), Some(7));
        assert_eq!(eval_int_literal("5UL"), Some(5));
        assert_eq!(eval_int_literal("012"), None); // leading-zero decimal rejected
        assert_eq!(eval_int_literal("abc"), None);
        assert_eq!(eval_int_literal(""), None);
    }

    // --- preprocess_view --------------------------------------------------

    #[test]
    fn non_c_language_is_identity() {
        let v = preprocess_view("python", "if False:\n    x\n", false, None);
        assert_eq!(v.fidelity, 0);
        assert_eq!(v.parse_text, "if False:\n    x\n");
    }

    #[test]
    fn c_blanks_dead_arm_preserving_lines() {
        let src = "int a;\n#if 0\nbad();\n#endif\nint b;\n";
        let v = preprocess_view("c", src, false, None);
        assert_eq!(v.fidelity, 1);
        // Line 3 (bad();) blanked to same-length spaces; line count unchanged.
        assert_eq!(v.parse_text.split('\n').count(), src.split('\n').count());
        assert_eq!(v.parse_text.split('\n').nth(2), Some(&*" ".repeat("bad();".len())));
        assert!(v.parse_text.contains("int a;"));
        assert!(v.parse_text.contains("int b;"));
    }

    #[test]
    fn isolation_mode_is_identity() {
        let src = "int a;\n#if 0\nbad();\n#endif\n";
        let v = preprocess_view("c", src, true, None);
        assert_eq!(v.fidelity, 0);
        assert_eq!(v.parse_text, src);
    }

    #[test]
    fn line_map_identity_is_passthrough() {
        assert_eq!(LineMap::identity().to_source(7), 7);
    }
}
