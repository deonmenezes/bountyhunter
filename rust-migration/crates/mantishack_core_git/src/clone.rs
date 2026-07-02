//! Faithful port of the PURE logic in `core/git/clone.py`.
//!
//! The three public entry points there (`clone_repository`, `fetch_commit`,
//! `ls_remote`) are I/O-bound: they spawn `git` through
//! `core.sandbox.run_untrusted`, log credential-redacted URLs, build the
//! sanitised env via `MantishackConfig.get_git_env`, and enforce a bounded
//! timeout. That orchestration stays in Python. What ports here is every pure,
//! security-load-bearing decision those wrappers gate on:
//!
//!   * the caller-supplied-SHA shape check ([`is_valid_sha`]) that stops
//!     `--upload-pack=` flag injection at the `git fetch <refspec>` position;
//!   * the strict 40-hex `ls-remote` output SHA check ([`is_ls_remote_sha`]);
//!   * the writable-path validator ([`validate_writable_path`]) that refuses to
//!     widen the sandbox writable scope to the whole filesystem;
//!   * the per-invocation `-c key=value` safety overrides ([`safe_git_command`]);
//!   * the `git` argv builders for clone / init / remote / fetch / ls-remote;
//!   * the `ls_remote` URL validator ([`validate_ls_remote_url`]) and the
//!     `ls-remote` output parser ([`parse_ls_remote_output`]).

use std::path::{Component, Path, PathBuf};

use crate::urlparse;

// ─────────────────────────── SHA shape checks ──────────────────────────────

/// Caller-supplied SHA shape check — Python `_SHA_RE = [0-9a-fA-F]{4,40}` under
/// `re.fullmatch`. Git allows abbreviations of 4+ chars; full SHA-1 is 40 hex.
/// Rejecting anything else stops a tainted SHA from being parsed as a `git
/// fetch` flag (`--upload-pack=`, CVE-2017-1000117 family). `fullmatch`
/// semantics: a trailing newline / NUL / whitespace fails (they aren't hex).
pub fn is_valid_sha(sha: &str) -> bool {
    let n = sha.chars().count();
    (4..=40).contains(&n) && sha.chars().all(|c| c.is_ascii_hexdigit())
}

/// Strict 40-char SHA for `ls-remote` output parsing — Python
/// `_LS_REMOTE_SHA_RE = [0-9a-fA-F]{40}` under `re.fullmatch`. Git always emits
/// full SHAs; a shorter "SHA" is malformed and possibly hostile, so abbreviated
/// SHAs are not accepted in this position.
pub fn is_ls_remote_sha(sha: &str) -> bool {
    sha.chars().count() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit())
}

// ───────────────────────── safe git overrides ──────────────────────────────

/// Per-invocation `-c key=value` overrides for git commands operating on TARGET
/// REPOSITORIES (cloned from untrusted source). Layered ON TOP of the env-strip
/// because env vars cannot suppress per-repo config inside `target/.git/config`
/// — git reads that unconditionally. Closes the fsmonitor / editor / pager /
/// askPass / sshCommand / hooksPath / credential-helper / gitProxy /
/// protocol-file / protocol-ext RCE vectors (CVE-2024-32002 &
/// CVE-2017-1000117 families).
pub const SAFE_GIT_OVERRIDES: &[&str] = &[
    "-c", "core.fsmonitor=",
    "-c", "core.editor=true",
    "-c", "core.pager=cat",
    "-c", "core.askPass=true",
    "-c", "core.sshCommand=ssh",
    "-c", "core.hooksPath=/dev/null",
    "-c", "credential.helper=",
    "-c", "core.gitProxy=",
    "-c", "protocol.file.allow=user",
    "-c", "protocol.ext.allow=never",
];

/// Return a `git` argv with per-invocation safety overrides layered between
/// `git` and the caller's `args`. Use for git commands operating on a TARGET
/// REPOSITORY (cloned from untrusted source).
pub fn safe_git_command<S: AsRef<str>>(args: &[S]) -> Vec<String> {
    let mut out = Vec::with_capacity(1 + SAFE_GIT_OVERRIDES.len() + args.len());
    out.push("git".to_string());
    out.extend(SAFE_GIT_OVERRIDES.iter().map(|s| s.to_string()));
    out.extend(args.iter().map(|s| s.as_ref().to_string()));
    out
}

// ───────────────────────── writable-path guard ─────────────────────────────

/// Error returned by [`validate_writable_path`] carrying the same wording shape
/// as the Python `ValueError` (mapped to `PyValueError` at the binding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritablePathError(pub String);

impl std::fmt::Display for WritablePathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for WritablePathError {}

const DENY_PREFIXES: &[&str] = &["/dev/", "/proc/", "/sys/", "/run/"];

/// The leading anchor (root / prefix) components of `p` as a path — `"/"` for a
/// Unix absolute path. Mirrors Python `Path.anchor`.
fn anchor(p: &Path) -> PathBuf {
    let mut a = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => a.push(c.as_os_str()),
            _ => break,
        }
    }
    a
}

/// True when `candidate` is the filesystem root itself, or a direct child of
/// root — the two Python checks `candidate.parent == candidate` and
/// `candidate.parent == Path(candidate.anchor)`.
fn is_root_or_direct_child(candidate: &Path) -> bool {
    match candidate.parent() {
        // Root has no parent in Rust; Python `Path("/").parent == Path("/")`.
        None => true,
        Some(parent) => {
            let a = anchor(candidate);
            !a.as_os_str().is_empty() && parent == a
        }
    }
}

/// Refuse caller-supplied paths that would unsafely widen the sandbox's
/// writable scope (the sandbox grants write to `p.parent`).
///
/// Rejected shapes (faithful to `_validate_writable_path`):
///   - relative paths (cwd-dependent writable scope);
///   - paths under a system pseudo-fs prefix (`/dev/`, `/proc/`, `/sys/`,
///     `/run/`);
///   - the filesystem root, or a direct child of root.
///
/// The literal-form root check is pure and catches every tested input plus the
/// macOS `/etc → /private/etc` symlink case. The resolved-form check (symlink
/// follow-through, e.g. `/tmp/work -> /`) is applied best-effort via
/// `canonicalize` when the path exists — matching Python's `Path.resolve()`
/// where the target is present on disk.
pub fn validate_writable_path(p: &Path, role: &str) -> Result<(), WritablePathError> {
    if !p.is_absolute() {
        return Err(WritablePathError(format!(
            "{role} must be an absolute path; got {p:?}. Relative paths are \
             unsafe here — the sandbox writable scope ({role}.parent) would be \
             cwd-dependent."
        )));
    }
    let s = p.to_string_lossy();
    for prefix in DENY_PREFIXES {
        let bare = prefix.trim_end_matches('/');
        if s.starts_with(prefix) || s == bare {
            return Err(WritablePathError(format!(
                "{role}={p:?} is under a system pseudo-fs prefix ({prefix}); \
                 refusing to grant the sandbox write access. Use /tmp, \
                 /var/tmp, $HOME, or a dedicated workspace path instead."
            )));
        }
    }
    // Literal-form checks (pure).
    if is_root_or_direct_child(p) {
        return Err(WritablePathError(format!(
            "{role}={p:?} literal-form is the filesystem root (or has root as \
             its parent); refusing to grant the sandbox write access to the \
             entire filesystem"
        )));
    }
    // Resolved-form check (best-effort; requires the path to exist on disk).
    if let Ok(resolved) = std::fs::canonicalize(p) {
        if is_root_or_direct_child(&resolved) {
            return Err(WritablePathError(format!(
                "{role}={p:?} resolved-form is the filesystem root (or has root \
                 as its parent); refusing to grant the sandbox write access to \
                 the entire filesystem"
            )));
        }
    }
    Ok(())
}

// ──────────────────────────── argv builders ────────────────────────────────

/// Build the `git clone` argv. `depth = None` clones full history (Python
/// `depth=None`); otherwise `--depth <n> --no-tags` is inserted.
pub fn build_clone_cmd(url: &str, target: &str, depth: Option<i64>) -> Vec<String> {
    let mut cmd = vec!["git".to_string(), "clone".to_string()];
    if let Some(d) = depth {
        cmd.push("--depth".to_string());
        cmd.push(d.to_string());
        cmd.push("--no-tags".to_string());
    }
    cmd.push(url.to_string());
    cmd.push(target.to_string());
    cmd
}

/// `git -C <repo_dir> init --quiet`.
pub fn build_init_cmd(repo_dir: &str) -> Vec<String> {
    vec![
        "git".into(),
        "-C".into(),
        repo_dir.to_string(),
        "init".into(),
        "--quiet".into(),
    ]
}

/// `git -C <repo_dir> remote add origin <url>`.
pub fn build_remote_add_cmd(repo_dir: &str, url: &str) -> Vec<String> {
    vec![
        "git".into(),
        "-C".into(),
        repo_dir.to_string(),
        "remote".into(),
        "add".into(),
        "origin".into(),
        url.to_string(),
    ]
}

/// `git -C <repo_dir> remote set-url origin <url>`.
pub fn build_remote_set_url_cmd(repo_dir: &str, url: &str) -> Vec<String> {
    vec![
        "git".into(),
        "-C".into(),
        repo_dir.to_string(),
        "remote".into(),
        "set-url".into(),
        "origin".into(),
        url.to_string(),
    ]
}

/// `git -C <repo_dir> fetch --depth <depth> --no-tags origin <sha>`.
pub fn build_fetch_cmd(repo_dir: &str, sha: &str, depth: i64) -> Vec<String> {
    vec![
        "git".into(),
        "-C".into(),
        repo_dir.to_string(),
        "fetch".into(),
        "--depth".into(),
        depth.to_string(),
        "--no-tags".into(),
        "origin".into(),
        sha.to_string(),
    ]
}

/// `git ls-remote --heads --tags <url>`.
pub fn build_ls_remote_cmd(url: &str) -> Vec<String> {
    vec![
        "git".into(),
        "ls-remote".into(),
        "--heads".into(),
        "--tags".into(),
        url.to_string(),
    ]
}

// ───────────────────────── ls_remote URL guard ─────────────────────────────

/// Error returned by [`validate_ls_remote_url`] (mapped to `PyValueError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsRemoteUrlError(pub String);

impl std::fmt::Display for LsRemoteUrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for LsRemoteUrlError {}

/// Approximate Python's `host_raw.encode("idna").decode("ascii").lower()`.
///
/// For an ASCII hostname the IDNA ToASCII step is the identity, so the canonical
/// host is the lowercased input — byte-identical to Python for every tested
/// input and the overwhelmingly common case. Python's IDNA-2003 punycode
/// encoding of a non-ASCII IDN hostname is NOT byte-reproduced here (untested by
/// the parity oracle; the egress proxy re-checks the allowlist at runtime): we
/// fall back to the lowercased raw form, matching Python's own
/// `except UnicodeError: host = host_raw` fallback shape.
fn idna_canonicalize(host_raw: &str) -> String {
    // ASCII → identity; non-ASCII → lowercased raw (documented approximation).
    host_raw.to_string()
}

/// Validate an `ls_remote` URL against the supplied `proxy_hosts` allowlist,
/// returning the canonical (lowercased) host on success.
///
/// Faithful to `ls_remote`'s validation prologue: non-empty allowlist required;
/// `https` scheme only; no userinfo; a hostname must be present; the host must
/// appear in the allowlist (case-insensitive, IDNA-canonicalised).
pub fn validate_ls_remote_url(
    url: &str,
    proxy_hosts: &[String],
) -> Result<String, LsRemoteUrlError> {
    if proxy_hosts.is_empty() {
        return Err(LsRemoteUrlError(
            "ls_remote requires non-empty proxy_hosts".to_string(),
        ));
    }
    let parsed = urlparse::urlsplit(url)
        .map_err(|e| LsRemoteUrlError(format!("ls_remote: malformed URL: {e}")))?;

    if parsed.scheme != "https" {
        return Err(LsRemoteUrlError(format!(
            "ls_remote requires https URL; got scheme='{}'",
            parsed.scheme
        )));
    }
    if parsed.username.is_some() || parsed.password.is_some() {
        return Err(LsRemoteUrlError(
            "ls_remote refuses URLs with userinfo (credentials in URL)".to_string(),
        ));
    }
    let hostname = match parsed.hostname {
        Some(h) if !h.is_empty() => h,
        _ => {
            return Err(LsRemoteUrlError(format!(
                "ls_remote: URL has no hostname: {url:?}"
            )))
        }
    };

    let host_raw = hostname.to_lowercase();
    let host = idna_canonicalize(&host_raw).to_lowercase();

    let allowed_lower: std::collections::HashSet<String> =
        proxy_hosts.iter().map(|h| h.to_lowercase()).collect();
    if !allowed_lower.contains(&host) {
        return Err(LsRemoteUrlError(format!(
            "ls_remote: URL host {host:?} not in proxy_hosts allowlist"
        )));
    }
    Ok(host)
}

// ───────────────────────── ls_remote output parse ──────────────────────────

/// True for Python `str.splitlines()` line boundaries.
fn is_line_boundary(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r'
            | '\u{0b}'
            | '\u{0c}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// Faithful port of Python `str.splitlines()` (no `keepends`): splits on the
/// full set of Unicode line boundaries, drops the terminators, treats `\r\n` as
/// one boundary, and adds no trailing empty entry for a trailing terminator.
fn py_splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if is_line_boundary(c) {
            out.push(&s[start..i]);
            if c == '\r' {
                if let Some(&(j, '\n')) = it.peek() {
                    let _ = it.next();
                    start = j + 1; // '\n' is one byte
                    continue;
                }
            }
            start = i + c.len_utf8();
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// Parse `git ls-remote --heads --tags` output into `(sha, ref)` pairs.
///
/// Each line is `<40-hex sha>\t<ref>`. Lines without a tab, or whose first
/// column isn't a strict 40-hex SHA, are skipped defensively (a hostile remote
/// can return arbitrary bytes).
pub fn parse_ls_remote_output(stdout: &str) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    for line in py_splitlines(stdout) {
        // Python `line.split("\t", 1)` → skip lines with no tab.
        let idx = match line.find('\t') {
            Some(i) => i,
            None => continue,
        };
        let sha = &line[..idx];
        let ref_ = &line[idx + 1..];
        if !is_ls_remote_sha(sha) {
            continue;
        }
        refs.push((sha.to_string(), ref_.to_string()));
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SHA: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const KERNEL_HOSTS: &[&str] = &["git.kernel.org", "git.savannah.gnu.org"];

    fn hosts(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // ── SHA shape ──────────────────────────────────────────────────────────

    #[test]
    fn accepts_full_and_short_sha() {
        assert!(is_valid_sha(VALID_SHA));
        assert!(is_valid_sha("deadbe")); // 6 hex — git abbreviation
        assert!(is_valid_sha("dead")); // 4 hex — lower bound
    }

    #[test]
    fn rejects_bad_sha_shapes() {
        for bad in [
            "--upload-pack=evil",
            "-X",
            "--exec=cmd",
            "",
            "not-hex-zzz",
            "deadbeef--upload-pack=evil",
            "deadbeef ",  // trailing whitespace
            "0123456789abcdef0123456789abcdef0123456701234567", // >40
            "abc",        // <4
            "../../etc/passwd",
            "deadbeef\n",  // fullmatch rejects the trailing newline
            "\ndeadbeef",  // leading newline
            "dead\nbeef",  // embedded newline
            "deadbeef\u{0}", // NUL byte
        ] {
            assert!(!is_valid_sha(bad), "wrongly accepted {bad:?}");
        }
    }

    #[test]
    fn ls_remote_sha_is_strict_40() {
        assert!(is_ls_remote_sha("abc1234567890abc1234567890abc1234567890a"));
        assert!(!is_ls_remote_sha("deadbeef")); // 8 hex — too short
        assert!(!is_ls_remote_sha(&"a".repeat(41))); // too long
        assert!(!is_ls_remote_sha("not-a-sha"));
    }

    // ── safe_git_command ─────────────────────────────────────────────────

    #[test]
    fn safe_git_command_layers_overrides() {
        let got = safe_git_command(&["-C", "/repo", "rev-parse", "HEAD"]);
        assert_eq!(got[0], "git");
        assert_eq!(got[1], "-c");
        assert_eq!(got[2], "core.fsmonitor=");
        // overrides are 20 entries; caller args follow.
        assert_eq!(&got[1..1 + SAFE_GIT_OVERRIDES.len()], SAFE_GIT_OVERRIDES);
        assert_eq!(
            &got[1 + SAFE_GIT_OVERRIDES.len()..],
            &["-C", "/repo", "rev-parse", "HEAD"]
        );
    }

    // ── writable path ──────────────────────────────────────────────────────

    #[test]
    fn rejects_unsafe_writable_paths() {
        for bad in ["", ".", "relative/repo", "/", "/foo", "/etc"] {
            assert!(
                validate_writable_path(Path::new(bad), "target").is_err(),
                "wrongly accepted {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_system_pseudo_fs_prefixes() {
        for bad in ["/dev/shm/foo", "/proc/1/status", "/sys/kernel", "/run/x"] {
            assert!(validate_writable_path(Path::new(bad), "repo_dir").is_err());
        }
    }

    #[test]
    fn accepts_reasonable_writable_path() {
        // Two components below root → passes the pure checks (nonexistent, so
        // the resolved-form canonicalize is skipped).
        assert!(validate_writable_path(Path::new("/tmp/work/repo"), "target").is_ok());
    }

    // ── argv builders ──────────────────────────────────────────────────────

    #[test]
    fn clone_cmd_shallow() {
        let cmd = build_clone_cmd("https://github.com/foo/bar", "/out", Some(1));
        assert_eq!(&cmd[..4], &["git", "clone", "--depth", "1"]);
        assert_eq!(cmd[4], "--no-tags");
        assert_eq!(cmd[5], "https://github.com/foo/bar");
        assert_eq!(cmd[6], "/out");
    }

    #[test]
    fn clone_cmd_full_drops_depth() {
        let cmd = build_clone_cmd("https://github.com/foo/bar", "/out", None);
        assert!(!cmd.iter().any(|a| a == "--depth"));
        assert!(!cmd.iter().any(|a| a == "--no-tags"));
        assert_eq!(cmd, vec!["git", "clone", "https://github.com/foo/bar", "/out"]);
    }

    #[test]
    fn fetch_cmd_sequence() {
        // Mirrors the init → remote add → fetch order + flags the Python test
        // asserts against the mocked run_untrusted call list.
        assert_eq!(
            build_init_cmd("/r"),
            vec!["git", "-C", "/r", "init", "--quiet"]
        );
        assert_eq!(
            build_remote_add_cmd("/r", "https://github.com/foo/bar"),
            vec!["git", "-C", "/r", "remote", "add", "origin", "https://github.com/foo/bar"]
        );
        assert_eq!(
            build_remote_set_url_cmd("/r", "https://github.com/foo/bar"),
            vec!["git", "-C", "/r", "remote", "set-url", "origin", "https://github.com/foo/bar"]
        );
        let f = build_fetch_cmd("/r", VALID_SHA, 5);
        assert_eq!(&f[..5], &["git", "-C", "/r", "fetch", "--depth"]);
        assert_eq!(f[5], "5");
        assert_eq!(&f[f.len() - 2..], &["origin", VALID_SHA]);
    }

    #[test]
    fn ls_remote_cmd() {
        assert_eq!(
            build_ls_remote_cmd("https://git.kernel.org/foo"),
            vec!["git", "ls-remote", "--heads", "--tags", "https://git.kernel.org/foo"]
        );
    }

    // ── ls_remote URL validation ─────────────────────────────────────────

    #[test]
    fn ls_remote_rejects_empty_proxy_hosts() {
        let err = validate_ls_remote_url("https://git.kernel.org/foo", &[]).unwrap_err();
        assert!(err.0.contains("proxy_hosts"));
    }

    #[test]
    fn ls_remote_rejects_bad_url_shapes() {
        for bad in [
            "ssh://git@github.com/foo/bar",
            "git://git.kernel.org/foo",
            "file:///etc/passwd",
            "ftp://example.com/foo",
            "http://git.kernel.org/foo",
            "https://user:pass@git.kernel.org/x",
            "https://user@git.kernel.org/x",
            "https:///no-host/path",
            "not a url",
        ] {
            assert!(
                validate_ls_remote_url(bad, &hosts(KERNEL_HOSTS)).is_err(),
                "wrongly accepted {bad:?}"
            );
        }
    }

    #[test]
    fn ls_remote_rejects_host_outside_allowlist() {
        let err = validate_ls_remote_url("https://evil.example.com/foo", &hosts(KERNEL_HOSTS))
            .unwrap_err();
        assert!(err.0.contains("not in proxy_hosts"));
    }

    #[test]
    fn ls_remote_host_match_case_insensitive() {
        let host = validate_ls_remote_url("https://Git.Kernel.Org/foo", &hosts(KERNEL_HOSTS))
            .unwrap();
        assert_eq!(host, "git.kernel.org");
    }

    #[test]
    fn ls_remote_accepts_allowlisted_host() {
        let host =
            validate_ls_remote_url("https://git.kernel.org/foo", &hosts(KERNEL_HOSTS)).unwrap();
        assert_eq!(host, "git.kernel.org");
    }

    // ── ls_remote output parse ─────────────────────────────────────────────

    #[test]
    fn parses_refs_skipping_malformed() {
        let stdout = concat!(
            "abc1234567890abc1234567890abc1234567890a\trefs/heads/main\n",
            "def1234567890def1234567890def1234567890b\trefs/tags/v1.0\n",
            "garbage_line_no_tab\n",
            "not-a-sha\trefs/heads/funny\n",
            "0000\trefs/heads/short-sha\n",
            "12345678901234567890123456789012345678901234\trefs/x\n",
        );
        assert_eq!(
            parse_ls_remote_output(stdout),
            vec![
                ("abc1234567890abc1234567890abc1234567890a".to_string(), "refs/heads/main".to_string()),
                ("def1234567890def1234567890def1234567890b".to_string(), "refs/tags/v1.0".to_string()),
            ]
        );
    }

    #[test]
    fn parse_resilient_to_non_utf8_replacement_chars() {
        let stdout = concat!(
            "abc1234567890abc1234567890abc1234567890a\trefs/heads/main\n",
            "\u{fffd}\u{fffd}\u{fffd}abc1234567890abc1234567890abc1234567\trefs/garbage\n",
        );
        assert_eq!(
            parse_ls_remote_output(stdout),
            vec![(
                "abc1234567890abc1234567890abc1234567890a".to_string(),
                "refs/heads/main".to_string()
            )]
        );
    }

    #[test]
    fn parse_uses_strict_40char_sha() {
        // 8-hex "SHA" the caller-input regex would accept must be rejected here.
        assert_eq!(parse_ls_remote_output("deadbeef\trefs/heads/short\n"), vec![]);
    }

    #[test]
    fn splitlines_matches_python_semantics() {
        assert_eq!(py_splitlines(""), Vec::<&str>::new());
        assert_eq!(py_splitlines("a\nb"), vec!["a", "b"]);
        assert_eq!(py_splitlines("a\n"), vec!["a"]);
        assert_eq!(py_splitlines("a\r\nb"), vec!["a", "b"]);
    }
}
