//! Extract apt-get install package lists from Dockerfile RUN instructions —
//! Rust port of the pure helpers in `core/dockerfile/apt.py`. The top-level
//! `extract_apt_packages` (shlex tokenisation + `Instruction` walk) stays Python.

/// A single package declared by a Dockerfile `apt-get install` (`AptPackage`).
#[derive(Clone, Debug, PartialEq)]
pub struct AptPackage {
    pub name: String,
    pub version: Option<String>,
    pub arch: Option<String>,
    pub stage: Option<String>,
    pub line: i64,
}

/// Python `str.split(None, 1)`: strip leading whitespace, split off the first
/// whitespace-delimited token; the remainder has its leading whitespace stripped.
fn split_none_1(s: &str) -> (Option<&str>, &str) {
    let t = s.trim_start();
    if t.is_empty() {
        return (None, "");
    }
    match t.find(char::is_whitespace) {
        Some(i) => (Some(&t[..i]), t[i..].trim_start()),
        None => (Some(t), ""),
    }
}

/// Collapse a multi-line RUN's raw source into one shell command line, dropping
/// `#`-comments (`_flatten_run`).
pub fn flatten_run(raw: &str) -> String {
    let mut physical: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
    if let Some(first) = physical.first() {
        let (word, rest) = split_none_1(first);
        if word.map(|w| w.to_uppercase() == "RUN").unwrap_or(false) {
            physical[0] = rest.to_string();
        }
    }
    let mut chunks: Vec<String> = Vec::new();
    for ln in &physical {
        let mut s = ln.trim().to_string();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        if s.ends_with('\\') {
            s = s[..s.len() - 1].trim_end().to_string();
        }
        if let Some(idx) = inline_comment_start(&s) {
            s = s[..idx].trim_end().to_string();
        }
        if !s.is_empty() {
            chunks.push(s);
        }
    }
    chunks.join(" ")
}

/// Byte index where an inline shell comment starts (`_inline_comment_start`):
/// a `#` at the start of a word (position 0 or preceded by whitespace).
pub fn inline_comment_start(s: &str) -> Option<usize> {
    let mut prev: Option<char> = None;
    for (i, c) in s.char_indices() {
        if c == '#' && (i == 0 || prev.map(|p| p.is_whitespace()).unwrap_or(false)) {
            return Some(i);
        }
        prev = Some(c);
    }
    None
}

/// Strip leading `(` and trailing `)` (`_strip_subshell_paren`).
pub fn strip_subshell_paren(tok: &str) -> String {
    tok.trim_start_matches('(').trim_end_matches(')').to_string()
}

/// A `KEY=VALUE` shell env prefix (`_is_env_prefix`).
pub fn is_env_prefix(tok: &str) -> bool {
    if !tok.contains('=') || tok.starts_with('-') || tok.starts_with('=') {
        return false;
    }
    let name = tok.split_once('=').map(|(n, _)| n).unwrap_or("");
    match name.chars().next() {
        None => return false,
        Some(c) if c.is_numeric() => return false,
        _ => {}
    }
    name.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// A clean `$VAR` / `pkg=${VAR}` substitution (`_is_clean_var_substitution`).
pub fn is_clean_var_substitution(token: &str) -> bool {
    if token.contains('`') || token.contains("$(") {
        return false;
    }
    token.matches('{').count() == token.matches('}').count()
}

/// Parse `pkg`, `pkg=ver`, `pkg:arch`, or `pkg:arch=ver` (`_parse_pkg`);
/// `None` for non-package tokens.
pub fn parse_pkg(token: &str) -> Option<(String, Option<String>, Option<String>)> {
    if token.is_empty() || token.starts_with('=') || token.starts_with(':') {
        return None;
    }
    if token.starts_with('/') || token.starts_with("./") || token.starts_with("../") {
        return None;
    }
    if ["$(", ")", "`", "${", "}"].iter().any(|m| token.contains(m)) && !is_clean_var_substitution(token) {
        return None;
    }
    let mut name = token;
    let mut version: Option<String> = None;
    let mut arch: Option<String> = None;
    if let Some((n, v)) = name.split_once('=') {
        name = n;
        version = (!v.is_empty()).then(|| v.to_string());
    }
    if let Some((n, a)) = name.split_once(':') {
        name = n;
        arch = (!a.is_empty()).then(|| a.to_string());
    }
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), version, arch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_and_comments() {
        assert_eq!(flatten_run("RUN apt-get install -y \\\n  pkg1 \\\n  # comment\n  pkg2 # inline\n"), "apt-get install -y pkg1 pkg2");
        assert_eq!(flatten_run("echo hi\n#comment\nfoo"), "echo hi foo");
        assert_eq!(inline_comment_start("a b # c"), Some(4));
        assert_eq!(inline_comment_start("pkg#tag"), None);
        assert_eq!(inline_comment_start("#x"), Some(0));
        assert_eq!(inline_comment_start("noc"), None);
    }

    #[test]
    fn parse_pkg_forms() {
        assert_eq!(parse_pkg("pkg"), Some(("pkg".into(), None, None)));
        assert_eq!(parse_pkg("pkg=1.2"), Some(("pkg".into(), Some("1.2".into()), None)));
        assert_eq!(parse_pkg("pkg:amd64"), Some(("pkg".into(), None, Some("amd64".into()))));
        assert_eq!(parse_pkg("pkg:amd64=1.2"), Some(("pkg".into(), Some("1.2".into()), Some("amd64".into()))));
        assert_eq!(parse_pkg("=x"), None);
        assert_eq!(parse_pkg("./a.deb"), None);
        assert_eq!(parse_pkg("$(cat"), None);
        assert_eq!(parse_pkg("pkg=${VAR}"), Some(("pkg".into(), Some("${VAR}".into()), None)));
        assert_eq!(parse_pkg("${VAR"), None); // unbalanced braces
        assert_eq!(parse_pkg("pkg`x`"), None);
        assert_eq!(parse_pkg(""), None);
    }

    #[test]
    fn env_paren_var() {
        assert!(is_env_prefix("KEY=val"));
        assert!(is_env_prefix("DEBIAN_FRONTEND=noninteractive"));
        assert!(!is_env_prefix("1BAD=x"));
        assert!(!is_env_prefix("-flag=x"));
        assert!(!is_env_prefix("a-b=x"));
        assert!(!is_env_prefix("=x"));

        assert_eq!(strip_subshell_paren("(apt-get"), "apt-get");
        assert_eq!(strip_subshell_paren(")"), "");
        assert_eq!(strip_subshell_paren("((y))"), "y");
        assert_eq!(strip_subshell_paren("normal"), "normal");

        assert!(is_clean_var_substitution("pkg=${VAR}"));
        assert!(is_clean_var_substitution("$VAR"));
        assert!(!is_clean_var_substitution("${VAR"));
        assert!(!is_clean_var_substitution("pkg`x`"));
        assert!(!is_clean_var_substitution("a}"));
    }
}
