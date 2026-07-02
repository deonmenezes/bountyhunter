//! Faithful port of `core/git/validate.py` — the repository-URL allowlist.
//!
//! Restricts `clone_repository` / `fetch_commit` to known-good hosting. Any URL
//! not matching one of the patterns is rejected fail-closed; this is a defence
//! against typosquat hostnames and accidental clones from attacker-supplied
//! URLs that route through unexpected hosts.
//!
//! Currently allows:
//!   - `https://github.com/<owner>/<repo>[/]`
//!   - `https://gitlab.com/<owner>/<repo>[/]`
//!   - `git@github.com:<owner>/<repo>.git`
//!   - `git@gitlab.com:<owner>/<repo>.git`

use fancy_regex::Regex;
use std::sync::OnceLock;

// Python uses `re.ASCII` so `\w` can't smuggle Cyrillic / homoglyph chars into
// the allowed owner/repo segment. We spell `\w` out as the explicit ASCII class
// `[0-9A-Za-z_]` (identical to `re.ASCII` `\w`) rather than relying on the
// regex engine's Unicode mode. The first char of each segment must be
// alphanumeric or underscore — refuses a leading `-` (which OpenSSH would parse
// as an option after argv translation, CVE-2017-1000117).
//
// Repo-name body is `[0-9A-Za-z_](?:[0-9A-Za-z_\-]|\.(?!\.))*` instead of a
// looser `[0-9A-Za-z_][\w.\-]*`. The looser body would accept repo names
// containing `..` (e.g. `.../foo/bar..`) because a `[\w.\-]*` star matches two
// consecutive dots. The negative lookahead `\.(?!\.)` after a `.` forbids a
// SECOND dot immediately, blocking `..` runs anywhere in the body while still
// allowing single-dot positions (`repo.name`, `foo.bar.git`).
//
// Each pattern is wrapped `\A(?:…)\z` to replicate Python's `re.fullmatch`:
// `\z` (not `$`) means a trailing newline is rejected — `re.match` + `$` would
// accept `"…repo/\n"`.
const OWNER: &str = r"[0-9A-Za-z_][0-9A-Za-z_\-]*";
const REPO_BODY: &str = r"[0-9A-Za-z_](?:[0-9A-Za-z_\-]|\.(?!\.))*";

fn patterns() -> &'static [Regex; 4] {
    static PATS: OnceLock<[Regex; 4]> = OnceLock::new();
    PATS.get_or_init(|| {
        let build = |p: String| Regex::new(&format!(r"\A(?:{})\z", p)).unwrap();
        [
            build(format!(r"https://github\.com/{}/{}/?", OWNER, REPO_BODY)),
            build(format!(r"https://gitlab\.com/{}/{}/?", OWNER, REPO_BODY)),
            build(format!(r"git@github\.com:{}/{}\.git", OWNER, REPO_BODY)),
            build(format!(r"git@gitlab\.com:{}/{}\.git", OWNER, REPO_BODY)),
        ]
    })
}

/// Return `true` if `url` matches one of the allowlist patterns.
///
/// Uses full-string anchoring (`\A…\z`) so a trailing newline (or any other
/// char) is rejected — mirroring Python's `re.fullmatch`. URLs longer than 2048
/// characters (Python `len`, i.e. Unicode code points) are rejected up front as
/// a DoS guard.
pub fn validate_repo_url(url: &str) -> bool {
    if url.chars().count() > 2048 {
        return false;
    }
    patterns()
        .iter()
        .any(|p| p.is_match(url).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_https_accepted() {
        assert!(validate_repo_url("https://github.com/torvalds/linux"));
        assert!(validate_repo_url("https://github.com/torvalds/linux/"));
        assert!(validate_repo_url("https://github.com/foo-bar/baz_qux.git"));
    }

    #[test]
    fn gitlab_https_accepted() {
        assert!(validate_repo_url("https://gitlab.com/foo/bar"));
    }

    #[test]
    fn ssh_form_accepted() {
        assert!(validate_repo_url("git@github.com:foo/bar.git"));
        assert!(validate_repo_url("git@gitlab.com:foo/bar.git"));
    }

    #[test]
    fn other_hosts_rejected() {
        assert!(!validate_repo_url("https://bitbucket.org/foo/bar"));
        assert!(!validate_repo_url("https://example.com/repo"));
        assert!(!validate_repo_url("https://github.com.evil.com/foo/bar"));
    }

    #[test]
    fn protocol_smuggling_rejected() {
        assert!(!validate_repo_url("ftp://github.com/foo/bar"));
        assert!(!validate_repo_url("file:///etc/passwd"));
        assert!(!validate_repo_url("https://github.com/foo/bar; rm -rf /"));
    }

    #[test]
    fn empty_or_malformed_rejected() {
        assert!(!validate_repo_url(""));
        assert!(!validate_repo_url("not a url"));
        assert!(!validate_repo_url("https://github.com")); // no path
        assert!(!validate_repo_url("https://github.com/foo")); // no repo
    }

    #[test]
    fn double_dot_in_repo_name_rejected() {
        // Regression coverage for the `..`-rejection fix. Mirrors the
        // parametrised Python test verbatim.
        for url in [
            "https://github.com/foo/bar..",
            "https://github.com/foo/bar...",
            "https://github.com/foo/..bar",
            "https://github.com/foo/ba..r",
            "https://github.com/foo../bar",
            "https://gitlab.com/foo/bar..",
            "https://gitlab.com/foo/ba..r",
            "git@github.com:foo/bar...git",
            "git@gitlab.com:foo/ba..r.git",
        ] {
            assert!(!validate_repo_url(url), "wrongly accepted {url:?}");
        }
    }

    #[test]
    fn single_dot_in_repo_name_still_accepted() {
        assert!(validate_repo_url("https://github.com/foo/bar.name"));
        assert!(validate_repo_url("https://github.com/foo/foo.bar.git"));
        assert!(validate_repo_url("https://gitlab.com/foo/foo.bar"));
    }

    #[test]
    fn single_trailing_dot_accepted() {
        // Golden (live Python): `\.(?!\.)` allows a single trailing dot
        // because the lookahead sees end-of-string, not another dot.
        assert!(validate_repo_url("https://github.com/foo/bar."));
    }

    #[test]
    fn leading_dash_rejected() {
        // Golden (live Python): owner/repo must start with `\w`.
        assert!(!validate_repo_url("https://github.com/-foo/bar"));
        assert!(!validate_repo_url("https://github.com/foo/-bar"));
    }

    #[test]
    fn ssh_without_dot_git_rejected() {
        // Golden (live Python): the scp-form patterns require a `.git` suffix.
        assert!(!validate_repo_url("git@github.com:foo/bar"));
    }

    #[test]
    fn trailing_newline_rejected() {
        // Golden (live Python): fullmatch (`\z`) rejects a trailing newline
        // that `re.match` + `$` would sneak through.
        assert!(!validate_repo_url("https://github.com/foo/bar\n"));
    }

    #[test]
    fn length_limit_boundary() {
        // Validator caps URLs at 2048 chars. Construct length-2048 / -2049
        // URLs by padding the repo name.
        let base = "https://github.com/owner/";
        let pad = 2048 - base.chars().count();
        let at_limit = format!("{base}{}", "a".repeat(pad));
        let over_limit = format!("{base}{}", "a".repeat(pad + 1));
        assert_eq!(at_limit.chars().count(), 2048);
        assert_eq!(over_limit.chars().count(), 2049);
        assert!(validate_repo_url(&at_limit));
        assert!(!validate_repo_url(&over_limit));
    }

    #[test]
    fn non_ascii_word_char_rejected() {
        // `re.ASCII` semantics: a Cyrillic homoglyph must NOT match `\w`.
        assert!(!validate_repo_url("https://github.com/\u{0430}/bar"));
    }
}
