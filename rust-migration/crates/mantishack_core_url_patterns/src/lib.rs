//! Canonical URL regex patterns + helpers for commit URL extraction.
//!
//! Faithful Rust rewrite of `core/url_patterns/__init__.py`.
//! Same inputs → same outputs, including every documented quirk.

use regex::Regex;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Compiled regexes (lazy, thread-safe)
// ---------------------------------------------------------------------------

/// Matches a GitHub commit URL and captures `owner/repo` (group 1) and SHA (group 2).
/// SHA bounds: {7,64} to accept both SHA-1 and SHA-256 git object names.
pub fn github_commit_url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)https?://github\.com/([^/]+/[^/#?\s]+)/commit/([a-f0-9]{7,64})\b",
        )
        .expect("GITHUB_COMMIT_URL_RE failed to compile")
    })
}

/// Matches a GitHub repo URL and captures `owner/repo` (group 1).
pub fn github_repo_url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)https?://github\.com/([^/]+/[^/#?\s]+)")
            .expect("GITHUB_REPO_URL_RE failed to compile")
    })
}

/// Matches a kernel.org SHA URL and captures the SHA (group 1).
pub fn kernel_sha_url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:kernel\.dance/|git\.kernel\.org/(?:linus|stable)/(?:c/)?)([a-f0-9]{7,64})\b",
        )
        .expect("KERNEL_SHA_URL_RE failed to compile")
    })
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Canonical slug for the mainline Linux kernel repository.
pub const LINUX_UPSTREAM_SLUG: &str = "torvalds/linux";

/// Number of hex characters to display when showing a shortened SHA.
pub const SHA_DISPLAY_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/// Lower-case, strip `.git` suffix, strip whitespace, strip trailing punctuation.
///
/// Trailing chars in `)]>,.;` are stripped iteratively before the `.git` strip
/// so that prose-embedded URLs like `foo/bar).` normalise to `foo/bar`.
pub fn normalize_slug(slug: &str) -> String {
    let mut slug = slug.trim().to_string();
    // Strip trailing punctuation iteratively (multiple chars may have been
    // captured: e.g. `slug.,`).
    while slug.ends_with(|c| ")\"]>,.;".contains(c)) {
        slug.pop();
    }
    if slug.ends_with(".git") {
        slug.truncate(slug.len() - 4);
    }
    slug.to_lowercase()
}

/// Return the canonical `owner/repo` slug from any GitHub URL, or `None`.
///
/// Uses regex `.find` (search anywhere in string), not anchored match — advisory
/// text often embeds GitHub URLs in prose.
pub fn extract_github_slug(url: &str) -> Option<String> {
    let caps = github_repo_url_re().captures(url)?;
    let group1 = caps.get(1)?.as_str();
    Some(normalize_slug(group1))
}

/// Lowercase hostname from a URL, or empty string on parse failure.
fn hostname(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
        .unwrap_or_default()
}

/// Hostname-anchored check for github.com and its subdomains.
pub fn is_github_url(url: &str) -> bool {
    let h = hostname(url);
    h == "github.com" || h.ends_with(".github.com")
}

/// Hostname-anchored check for gitlab.com (not self-hosted).
pub fn is_gitlab_url(url: &str) -> bool {
    let h = hostname(url);
    h == "gitlab.com" || h.ends_with(".gitlab.com")
}

/// Hostname-anchored check for kernel.org and subdomains.
pub fn is_kernel_org_url(url: &str) -> bool {
    let h = hostname(url);
    h == "kernel.org" || h.ends_with(".kernel.org")
}

// ---------------------------------------------------------------------------
// PyO3 bindings (feature = "python")
// ---------------------------------------------------------------------------

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pyfunction]
fn py_normalize_slug(slug: &str) -> String {
    normalize_slug(slug)
}

#[cfg(feature = "python")]
#[pyfunction]
fn py_extract_github_slug(url: &str) -> Option<String> {
    extract_github_slug(url)
}

#[cfg(feature = "python")]
#[pyfunction]
fn py_is_github_url(url: &str) -> bool {
    is_github_url(url)
}

#[cfg(feature = "python")]
#[pyfunction]
fn py_is_gitlab_url(url: &str) -> bool {
    is_gitlab_url(url)
}

#[cfg(feature = "python")]
#[pyfunction]
fn py_is_kernel_org_url(url: &str) -> bool {
    is_kernel_org_url(url)
}

#[cfg(feature = "python")]
#[pymodule]
fn mantishack_core_url_patterns(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_normalize_slug, m)?)?;
    m.add_function(wrap_pyfunction!(py_extract_github_slug, m)?)?;
    m.add_function(wrap_pyfunction!(py_is_github_url, m)?)?;
    m.add_function(wrap_pyfunction!(py_is_gitlab_url, m)?)?;
    m.add_function(wrap_pyfunction!(py_is_kernel_org_url, m)?)?;
    m.add("LINUX_UPSTREAM_SLUG", LINUX_UPSTREAM_SLUG)?;
    m.add("SHA_DISPLAY_LEN", SHA_DISPLAY_LEN)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — golden vectors derived by running the Python source
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- normalize_slug -------------------------------------------------------

    #[test]
    fn test_normalize_slug_git_suffix() {
        // Python: normalize_slug('Foo/Bar.git') -> 'foo/bar'
        assert_eq!(normalize_slug("Foo/Bar.git"), "foo/bar");
    }

    #[test]
    fn test_normalize_slug_whitespace() {
        // Python: normalize_slug('  foo/bar  ') -> 'foo/bar'
        assert_eq!(normalize_slug("  foo/bar  "), "foo/bar");
    }

    #[test]
    fn test_normalize_slug_trailing_paren_dot() {
        // Python: normalize_slug('foo/bar).') -> 'foo/bar'
        assert_eq!(normalize_slug("foo/bar)."), "foo/bar");
    }

    #[test]
    fn test_normalize_slug_multiple_trailing_punct() {
        // Python: normalize_slug('foo/bar]>,;') -> 'foo/bar'
        assert_eq!(normalize_slug("foo/bar]>,;"), "foo/bar");
    }

    #[test]
    fn test_normalize_slug_plain_git() {
        // Python: normalize_slug('foo/bar.git') -> 'foo/bar'
        assert_eq!(normalize_slug("foo/bar.git"), "foo/bar");
    }

    #[test]
    fn test_normalize_slug_uppercase() {
        // Python: normalize_slug('FOO/BAR') -> 'foo/bar'
        assert_eq!(normalize_slug("FOO/BAR"), "foo/bar");
    }

    #[test]
    fn test_normalize_slug_empty() {
        // Python: normalize_slug('') -> ''
        assert_eq!(normalize_slug(""), "");
    }

    #[test]
    fn test_normalize_slug_plain() {
        // Python: normalize_slug('foo/bar') -> 'foo/bar'
        assert_eq!(normalize_slug("foo/bar"), "foo/bar");
    }

    // --- extract_github_slug -------------------------------------------------

    #[test]
    fn test_extract_github_slug_plain_url() {
        // Python: extract_github_slug('https://github.com/foo/bar') -> 'foo/bar'
        assert_eq!(
            extract_github_slug("https://github.com/foo/bar"),
            Some("foo/bar".to_string())
        );
    }

    #[test]
    fn test_extract_github_slug_embedded_in_prose() {
        // Python: extract_github_slug('see https://github.com/foo/bar).') -> 'foo/bar'
        assert_eq!(
            extract_github_slug("see https://github.com/foo/bar)."),
            Some("foo/bar".to_string())
        );
    }

    #[test]
    fn test_extract_github_slug_commit_url() {
        // Python: extract_github_slug('Mitigated by https://github.com/torvalds/linux/commit/abc1234')
        //         -> 'torvalds/linux'
        assert_eq!(
            extract_github_slug(
                "Mitigated by https://github.com/torvalds/linux/commit/abc1234"
            ),
            Some("torvalds/linux".to_string())
        );
    }

    #[test]
    fn test_extract_github_slug_non_github() {
        // Python: extract_github_slug('https://notgithub.com/foo/bar') -> None
        assert_eq!(extract_github_slug("https://notgithub.com/foo/bar"), None);
    }

    #[test]
    fn test_extract_github_slug_empty() {
        // Python: extract_github_slug('') -> None
        assert_eq!(extract_github_slug(""), None);
    }

    #[test]
    fn test_extract_github_slug_uppercase_dotgit() {
        // Python: extract_github_slug('https://github.com/FOO/BAR.git') -> 'foo/bar'
        assert_eq!(
            extract_github_slug("https://github.com/FOO/BAR.git"),
            Some("foo/bar".to_string())
        );
    }

    // --- is_github_url -------------------------------------------------------

    #[test]
    fn test_is_github_url_plain() {
        // Python: is_github_url('https://github.com/foo/bar') -> True
        assert!(is_github_url("https://github.com/foo/bar"));
    }

    #[test]
    fn test_is_github_url_subdomain() {
        // Python: is_github_url('https://api.github.com/repos/foo/bar') -> True
        assert!(is_github_url("https://api.github.com/repos/foo/bar"));
    }

    #[test]
    fn test_is_github_url_rejects_gitlab() {
        // Python: is_github_url('https://gitlab.com/foo/bar') -> False
        assert!(!is_github_url("https://gitlab.com/foo/bar"));
    }

    #[test]
    fn test_is_github_url_empty() {
        // Python: is_github_url('') -> False
        assert!(!is_github_url(""));
    }

    // --- is_gitlab_url -------------------------------------------------------

    #[test]
    fn test_is_gitlab_url_plain() {
        // Python: is_gitlab_url('https://gitlab.com/foo/bar') -> True
        assert!(is_gitlab_url("https://gitlab.com/foo/bar"));
    }

    #[test]
    fn test_is_gitlab_url_non_gitlab_subdomain() {
        // Python: is_gitlab_url('https://gitlab.freedesktop.org/foo/bar') -> False
        // hostname = gitlab.freedesktop.org, does not end with .gitlab.com
        assert!(!is_gitlab_url("https://gitlab.freedesktop.org/foo/bar"));
    }

    #[test]
    fn test_is_gitlab_url_rejects_github() {
        // Python: is_gitlab_url('https://github.com/foo/bar') -> False
        assert!(!is_gitlab_url("https://github.com/foo/bar"));
    }

    // --- is_kernel_org_url ---------------------------------------------------

    #[test]
    fn test_is_kernel_org_url_subdomain() {
        // Python: is_kernel_org_url('https://git.kernel.org/linus/abc1234') -> True
        assert!(is_kernel_org_url("https://git.kernel.org/linus/abc1234"));
    }

    #[test]
    fn test_is_kernel_org_url_apex() {
        // Python: is_kernel_org_url('https://kernel.org/pub/linux') -> True
        assert!(is_kernel_org_url("https://kernel.org/pub/linux"));
    }

    #[test]
    fn test_is_kernel_org_url_rejects_github() {
        // Python: is_kernel_org_url('https://github.com/foo/bar') -> False
        assert!(!is_kernel_org_url("https://github.com/foo/bar"));
    }

    // --- KERNEL_SHA_URL_RE captures ------------------------------------------

    #[test]
    fn test_kernel_sha_re_kernel_dance() {
        // Python: KERNEL_SHA_URL_RE.search('https://kernel.dance/abc1234def5678').group(1)
        //         -> 'abc1234def5678'
        let caps = kernel_sha_url_re()
            .captures("https://kernel.dance/abc1234def5678")
            .expect("should match");
        assert_eq!(caps.get(1).unwrap().as_str(), "abc1234def5678");
    }

    #[test]
    fn test_kernel_sha_re_linus() {
        // Python: KERNEL_SHA_URL_RE.search('https://git.kernel.org/linus/abc1234def5678').group(1)
        //         -> 'abc1234def5678'
        let caps = kernel_sha_url_re()
            .captures("https://git.kernel.org/linus/abc1234def5678")
            .expect("should match");
        assert_eq!(caps.get(1).unwrap().as_str(), "abc1234def5678");
    }

    #[test]
    fn test_kernel_sha_re_stable_c() {
        // Python: KERNEL_SHA_URL_RE.search('https://git.kernel.org/stable/c/abc1234def5678').group(1)
        //         -> 'abc1234def5678'
        let caps = kernel_sha_url_re()
            .captures("https://git.kernel.org/stable/c/abc1234def5678")
            .expect("should match");
        assert_eq!(caps.get(1).unwrap().as_str(), "abc1234def5678");
    }

    // --- constants -----------------------------------------------------------

    #[test]
    fn test_constants() {
        assert_eq!(LINUX_UPSTREAM_SLUG, "torvalds/linux");
        assert_eq!(SHA_DISPLAY_LEN, 12);
    }
}
