//! Faithful Rust port of the **pure logic** in `core/http/urllib_backend.py`.
//!
//! The `UrllibClient` in Python is a urllib3-backed HTTP client. The actual
//! network I/O — pool-manager / proxy-manager construction, the retry loop with
//! its `time.sleep` backoff, response streaming, gzip decode of the live body,
//! and the `_fetch` / `_fetch_once` / `_stream` methods — is I/O-bound and
//! **stays in Python by design**. What is ported here is the deterministic,
//! side-effect-free logic those methods depend on:
//!
//!   * [`validate_url`] — the `_validate_url` entry guard: byte-length cap,
//!     scheme allowlist, host-presence, embedded-credential rejection, backed
//!     by a faithful re-implementation of Python's `urllib.parse.urlsplit`
//!     field extraction ([`urlsplit`]).
//!   * [`HostCircuitBreaker`] — the per-`(host, port)` rate-limit circuit
//!     breaker state machine (`_HostCircuitBreaker`).
//!   * [`parse_retry_after`] — `Retry-After` header parsing (delta-seconds and
//!     HTTP-date forms) with the `[1, 1800]` clamp.
//!   * [`is_proxy_forbidden`] — the ProxyError "403 / host-off-allowlist"
//!     message classification (permanent vs transient).
//!   * [`is_transient_status`] / [`compute_max_attempts`] / [`BACKOFF_SECONDS`]
//!     — the retry-loop arithmetic (which status codes retry, how many attempts
//!     the schedule permits) and the import-time schedule ↔ `DEFAULT_RETRIES`
//!     drift guard.
//!   * [`looks_gzip`] — the magic-byte sniff for the defence-in-depth gzip
//!     fallback.
//!   * [`collapse_headers`] — the lowercase-key, newline-join-multi-value header
//!     collapse applied to a response's header list.
//!
//! Secret redaction for log/error lines (`_safe_url_for_log`, the 4xx snippet
//! `redact_secrets` call) depends on `core.security.redaction`, which is **not**
//! ported to the Rust `mantishack_core_security` crate; those log-shaping paths
//! live entirely inside the Python I/O methods and stay Python.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use regex::Regex;

use crate::HttpError;

// ─────────────────────────── constants ─────────────────────────────────────

/// `_DEFAULT_POOL_MAXSIZE` — connections per (host, port) pool.
pub const DEFAULT_POOL_MAXSIZE: usize = 10;

/// `_MAX_URL_BYTES` — hard cap on the wire-length of a URL (64 KiB).
pub const MAX_URL_BYTES: usize = 64 * 1024;

/// `UrllibClient._ALLOWED_SCHEMES`.
pub const URLLIB_ALLOWED_SCHEMES: &[&str] = &["http", "https"];

/// `_BACKOFF_SECONDS` — backoff schedule; one slot per attempt.
pub const BACKOFF_SECONDS: [i64; 6] = [1, 2, 5, 15, 60, 300];

// Import-time drift guard (Python raises RuntimeError if this fails). Enforced
// here at compile time: one schedule slot for the initial attempt + one per
// retry, i.e. `len(_BACKOFF_SECONDS) == DEFAULT_RETRIES + 1`.
const _: () = assert!(BACKOFF_SECONDS.len() == (crate::DEFAULT_RETRIES as usize) + 1);

// ─────────────────────────── retry arithmetic ──────────────────────────────

/// Transient-status classification from `_fetch`: retry only on 429 and 5xx.
///
/// Mirrors `e.status == 429 or (e.status is not None and 500 <= e.status < 600)`.
pub fn is_transient_status(status: Option<i64>) -> bool {
    match status {
        Some(429) => true,
        Some(s) => (500..600).contains(&s),
        None => false,
    }
}

/// `max(1, min(retries + 1, len(_BACKOFF_SECONDS)))` — number of attempts the
/// schedule permits for the caller's `retries` cap. `retries=0` → 1 attempt.
pub fn compute_max_attempts(retries: i64) -> usize {
    let capped = std::cmp::min(retries + 1, BACKOFF_SECONDS.len() as i64);
    std::cmp::max(1, capped) as usize
}

// ─────────────────────────── gzip sniff ────────────────────────────────────

/// The defence-in-depth gzip magic-byte check: `raw.startswith(b"\x1f\x8b")`.
pub fn looks_gzip(data: &[u8]) -> bool {
    data.starts_with(&[0x1f, 0x8b])
}

// ─────────────────────────── proxy 403 classification ──────────────────────

fn proxy_403_status_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:status|http|tunnel|response)[^\n]{0,40}\b403\b").unwrap()
    })
}

fn proxy_403_forbidden_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b403\s+forbidden\b").unwrap())
}

/// Classify a `urllib3.ProxyError` message: `True` means the in-process proxy
/// refused the host (a permanent, off-allowlist 403 — do NOT retry); `False`
/// means treat as transient (e.g. proxy unreachable — retry).
///
/// Mirrors the two anchored regexes in `_fetch`'s `_U3ProxyError` handler,
/// matched against the lower-cased message.
pub fn is_proxy_forbidden(message: &str) -> bool {
    let msg = message.to_lowercase();
    proxy_403_status_re().is_match(&msg) || proxy_403_forbidden_re().is_match(&msg)
}

// ─────────────────────────── header collapse ───────────────────────────────

/// Collapse a response's raw header list to the `Response.headers` mapping:
/// keys lower-cased, values for a repeated header newline-joined, first-seen
/// order preserved. Mirrors the `getlist` collapse loop in `_fetch_once`.
pub fn collapse_headers(entries: &[(String, String)]) -> Vec<(String, String)> {
    let mut order: Vec<String> = Vec::new();
    let mut map: HashMap<String, String> = HashMap::new();
    for (name, value) in entries {
        let lk = name.to_lowercase();
        match map.get_mut(&lk) {
            Some(existing) => {
                existing.push('\n');
                existing.push_str(value);
            }
            None => {
                order.push(lk.clone());
                map.insert(lk, value.clone());
            }
        }
    }
    order
        .into_iter()
        .map(|k| {
            let v = map.remove(&k).unwrap_or_default();
            (k, v)
        })
        .collect()
}

// ─────────────────────────── URL validation ────────────────────────────────

/// Faithful subset of `urllib.parse.urlsplit` — the fields `_validate_url`
/// reads: `scheme` (lower-cased), `hostname` (empty → `None`, else lower-cased),
/// `username`, `password`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitResult {
    pub scheme: String,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.'
}

/// Re-implementation of `urllib.parse.urlsplit` for the fields the validator
/// needs. Returns `Err(message)` for the malformed cases where CPython's
/// `urlsplit` itself raises `ValueError` (unbalanced IPv6 brackets).
pub fn urlsplit(url_in: &str) -> Result<SplitResult, String> {
    // `_UNSAFE_URL_BYTES_TO_REMOVE = ["\t", "\r", "\n"]` — stripped, not rejected.
    let mut url: String = url_in
        .chars()
        .filter(|c| *c != '\t' && *c != '\r' && *c != '\n')
        .collect();

    // Scheme: chars before the first ':' must all be scheme chars.
    let mut scheme = String::new();
    if let Some(i) = url.find(':') {
        if i > 0 {
            let pre = &url[..i];
            if pre.chars().all(is_scheme_char) {
                scheme = pre.to_ascii_lowercase();
                url = url[i + 1..].to_string();
            }
        }
    }

    // netloc when the remainder starts with "//".
    let mut netloc = String::new();
    if let Some(rest) = url.strip_prefix("//") {
        let mut end = rest.len();
        for (idx, c) in rest.char_indices() {
            if c == '/' || c == '?' || c == '#' {
                end = idx;
                break;
            }
        }
        netloc = rest[..end].to_string();
        let has_open = netloc.contains('[');
        let has_close = netloc.contains(']');
        if has_open != has_close {
            return Err("Invalid IPv6 URL".to_string());
        }
    }

    // userinfo split on the LAST '@' (rpartition).
    let (userinfo, hostinfo) = match netloc.rfind('@') {
        Some(at) => (Some(netloc[..at].to_string()), netloc[at + 1..].to_string()),
        None => (None, netloc.clone()),
    };
    let (username, password) = match userinfo {
        Some(ui) => match ui.find(':') {
            Some(c) => (Some(ui[..c].to_string()), Some(ui[c + 1..].to_string())),
            None => (Some(ui), None),
        },
        None => (None, None),
    };

    // host: bracketed IPv6 → between '[' and ']', else up to the first ':'.
    let raw_host = if let Some(ob) = hostinfo.find('[') {
        let after = &hostinfo[ob + 1..];
        match after.find(']') {
            Some(cb) => after[..cb].to_string(),
            None => after.to_string(),
        }
    } else {
        match hostinfo.find(':') {
            Some(c) => hostinfo[..c].to_string(),
            None => hostinfo.clone(),
        }
    };
    let hostname = if raw_host.is_empty() {
        None
    } else {
        Some(raw_host.to_ascii_lowercase())
    };

    Ok(SplitResult {
        scheme,
        hostname,
        username,
        password,
    })
}

/// Successful result of [`validate_url`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedUrl {
    pub scheme: String,
    pub host: String,
}

/// Port of `UrllibClient._validate_url`. Rejects (in order) over-long URLs,
/// malformed URLs, disallowed schemes, host-less URLs and embedded credentials,
/// mapping each Python `HttpError` to an [`HttpError`] with the same message.
pub fn validate_url(url: &str, allowed_schemes: &[&str]) -> Result<ValidatedUrl, HttpError> {
    // Length cap compares wire bytes; for a Rust `str` the UTF-8 byte length is
    // exactly what `url.encode("utf-8", errors="ignore")` would yield.
    if url.len() > MAX_URL_BYTES {
        return Err(HttpError::plain(format!(
            "Refused URL exceeding {}-byte cap (input was {} chars)",
            MAX_URL_BYTES,
            url.chars().count()
        )));
    }
    let parsed = urlsplit(url)
        .map_err(|e| HttpError::plain(format!("Refused malformed URL: {}", e)))?;
    if !allowed_schemes.iter().any(|s| *s == parsed.scheme) {
        let permitted = allowed_schemes.join("/");
        return Err(HttpError::plain(format!(
            "Refused URL with scheme {}: only {} permitted",
            py_repr(&parsed.scheme),
            permitted
        )));
    }
    let host = match parsed.hostname {
        Some(h) => h,
        None => {
            return Err(HttpError::plain(format!(
                "Refused URL with no host: {}",
                py_repr(url)
            )))
        }
    };
    if parsed.username.is_some() || parsed.password.is_some() {
        return Err(HttpError::plain(
            "Refused URL with embedded credentials; pass credentials via an \
             Authorization header, not in the URL authority"
                .to_string(),
        ));
    }
    Ok(ValidatedUrl {
        scheme: parsed.scheme,
        host,
    })
}

/// Minimal Python `repr()` for a `str`, matching CPython's quote selection and
/// escaping for the ASCII cases the validator's error messages exercise.
fn py_repr(s: &str) -> String {
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
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

// ─────────────────────────── Retry-After parsing ───────────────────────────

/// Port of `UrllibClient._parse_retry_after`. Parses both the delta-seconds and
/// the HTTP-date forms of `Retry-After`, clamping the result to `[1, 1800]`.
/// Returns `None` for absent / unparseable values.
pub fn parse_retry_after(value: Option<&str>) -> Option<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    parse_retry_after_at(value, now)
}

/// [`parse_retry_after`] with the "current time" (unix seconds) injected, so the
/// HTTP-date branch is deterministically testable.
pub fn parse_retry_after_at(value: Option<&str>, now_unix: f64) -> Option<i64> {
    let value = value?;
    // Python `if not value: return None` — the empty string short-circuits.
    if value.is_empty() {
        return None;
    }
    let s = value.trim();

    // Delta-seconds form: Python `int(s)`.
    if let Some(n) = py_int(s) {
        return Some(clamp_retry(n));
    }

    // HTTP-date form.
    let target = parse_http_date(s)?;
    let delta = target as f64 - now_unix;
    // Python `int(delta)` truncates toward zero.
    let delta_trunc = delta.trunc();
    let n = if delta_trunc >= i64::MAX as f64 {
        i128::from(i64::MAX)
    } else if delta_trunc <= i64::MIN as f64 {
        i128::from(i64::MIN)
    } else {
        delta_trunc as i128
    };
    Some(clamp_retry(n))
}

fn clamp_retry(n: i128) -> i64 {
    n.clamp(1, 1800) as i64
}

/// Parse an integer the way Python's `int(str)` does for the ASCII forms a
/// `Retry-After` header can carry: optional leading `+`/`-` then decimal digits.
/// Returns `None` for anything else (floats, empty, garbage) so the caller falls
/// through to the HTTP-date branch. Overly long digit runs saturate (Python's
/// `int` is unbounded, but the `[1, 1800]` clamp erases the difference).
fn py_int(s: &str) -> Option<i128> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let (neg, digits) = match bytes[0] {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut acc: i128 = 0;
    for b in digits.bytes() {
        acc = acc
            .saturating_mul(10)
            .saturating_add(i128::from(b - b'0'));
    }
    Some(if neg { -acc } else { acc })
}

fn month_num(tok: &str) -> Option<u32> {
    let t = tok.to_ascii_lowercase();
    let key: String = t.chars().take(3).collect();
    match key.as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

fn parse_u32(tok: &str) -> Option<u32> {
    if tok.is_empty() || !tok.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    tok.parse::<u32>().ok()
}

fn parse_year(tok: &str) -> Option<i64> {
    if tok.is_empty() || !tok.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let y: i64 = tok.parse().ok()?;
    // RFC 850 two-digit year normalisation (parsedate: <69 → 2000s, else 1900s).
    if tok.len() <= 2 {
        Some(if y >= 69 { 1900 + y } else { 2000 + y })
    } else {
        Some(y)
    }
}

fn parse_hms(tok: &str) -> Option<(u32, u32, u32)> {
    let mut parts = tok.split(':');
    let h = parse_u32(parts.next()?)?;
    let m = parse_u32(parts.next()?)?;
    let s = parse_u32(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    if h > 23 || m > 59 || s > 60 {
        return None;
    }
    Some((h, m, s))
}

/// Timezone offset in seconds to SUBTRACT from local wall-clock to get UTC.
/// `GMT`/`UTC`/`UT`/`Z` and unknown names → 0 (parsedate treats a missing/naive
/// tz as UTC here); numeric `±HHMM` offsets are honoured.
fn tz_offset(tok: &str) -> i64 {
    let b = tok.as_bytes();
    if (b[0] == b'+' || b[0] == b'-') && b.len() == 5 && b[1..].iter().all(|c| c.is_ascii_digit()) {
        let hh: i64 = tok[1..3].parse().unwrap_or(0);
        let mm: i64 = tok[3..5].parse().unwrap_or(0);
        let mag = hh * 3600 + mm * 60;
        return if b[0] == b'+' { mag } else { -mag };
    }
    0
}

/// Days from the civil date to the Unix epoch (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = ((month + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parse an HTTP-date into unix seconds. Handles IMF-fixdate and the
/// day-name-optional / asctime arrangements RFC 7231 permits; the weekday token
/// is ignored (matching `email.utils.parsedate_to_datetime`).
fn parse_http_date(s: &str) -> Option<i64> {
    let toks: Vec<&str> = s
        .split(|c: char| c.is_ascii_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .collect();
    if toks.is_empty() {
        return None;
    }
    let mut t = &toks[..];
    // Drop a leading weekday token (alphabetic, not a month name).
    if t[0].bytes().all(|b| b.is_ascii_alphabetic()) && month_num(t[0]).is_none() {
        t = &t[1..];
    }
    if t.len() < 4 {
        return None;
    }
    // IMF-fixdate / RFC 850: day month year time [tz].
    if let (Some(day), Some(mon), Some(year)) =
        (parse_u32(t[0]), month_num(t[1]), parse_year(t[2]))
    {
        if let Some((h, mi, se)) = parse_hms(t[3]) {
            let off = if t.len() >= 5 { tz_offset(t[4]) } else { 0 };
            let days = days_from_civil(year, mon, day);
            return Some(days * 86400 + h as i64 * 3600 + mi as i64 * 60 + se as i64 - off);
        }
    }
    // asctime: month day time year.
    if let (Some(mon), Some(day)) = (month_num(t[0]), parse_u32(t[1])) {
        if let Some((h, mi, se)) = parse_hms(t[2]) {
            if let Some(year) = parse_year(t[3]) {
                let days = days_from_civil(year, mon, day);
                return Some(days * 86400 + h as i64 * 3600 + mi as i64 * 60 + se as i64);
            }
        }
    }
    None
}

// ─────────────────────────── circuit breaker ───────────────────────────────

type Clock = Box<dyn Fn() -> f64 + Send + Sync>;

struct CbState {
    failures: HashMap<(String, i64), Vec<f64>>,
    open_until: HashMap<(String, i64), f64>,
}

/// Port of `_HostCircuitBreaker`: after `threshold` 429/5xx events for a
/// `(host, port)` within `window` seconds the circuit opens and stays open for
/// `cooldown` seconds; a success clears it. Thread-safe (Python used a `Lock`).
pub struct HostCircuitBreaker {
    threshold: usize,
    window: f64,
    cooldown: f64,
    state: Mutex<CbState>,
    clock: Clock,
}

impl HostCircuitBreaker {
    /// Default parameters: `threshold=2`, `window=60.0`, `cooldown=120.0`, with a
    /// monotonic clock (mirrors Python's `time.monotonic`).
    pub fn new() -> Self {
        Self::with_params(2, 60.0, 120.0)
    }

    /// Custom parameters with a monotonic clock.
    pub fn with_params(threshold: usize, window: f64, cooldown: f64) -> Self {
        let base = Instant::now();
        Self::with_clock(
            threshold,
            window,
            cooldown,
            Box::new(move || base.elapsed().as_secs_f64()),
        )
    }

    /// Custom parameters with an injected clock (for deterministic tests).
    pub fn with_clock(threshold: usize, window: f64, cooldown: f64, clock: Clock) -> Self {
        HostCircuitBreaker {
            threshold,
            window,
            cooldown,
            state: Mutex::new(CbState {
                failures: HashMap::new(),
                open_until: HashMap::new(),
            }),
            clock,
        }
    }

    fn key(host: &str, port: i64) -> (String, i64) {
        (host.to_ascii_lowercase(), port)
    }

    /// `(is_open, seconds_remaining)`. When open the caller must fail-fast.
    pub fn is_open(&self, host: &str, port: i64) -> (bool, f64) {
        let key = Self::key(host, port);
        let mut st = self.state.lock().unwrap();
        let now = (self.clock)();
        let until = *st.open_until.get(&key).unwrap_or(&0.0);
        if now < until {
            return (true, until - now);
        }
        if until != 0.0 {
            st.open_until.remove(&key);
        }
        (false, 0.0)
    }

    /// Record a 429/5xx. Returns `true` iff this call transitioned the circuit
    /// from closed to open.
    pub fn record_failure(&self, host: &str, port: i64) -> bool {
        let key = Self::key(host, port);
        let mut st = self.state.lock().unwrap();
        let now = (self.clock)();
        let window = self.window;
        let len = {
            let failures = st.failures.entry(key.clone()).or_default();
            failures.retain(|t| now - *t < window);
            failures.push(now);
            failures.len()
        };
        if len >= self.threshold {
            let was_open = now < *st.open_until.get(&key).unwrap_or(&0.0);
            st.open_until.insert(key, now + self.cooldown);
            return !was_open;
        }
        false
    }

    /// Reset state for the host on a 2xx response.
    pub fn record_success(&self, host: &str, port: i64) {
        let key = Self::key(host, port);
        let mut st = self.state.lock().unwrap();
        st.failures.remove(&key);
        st.open_until.remove(&key);
    }
}

impl Default for HostCircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // A controllable clock for the circuit breaker tests.
    fn fixed_clock() -> (HostCircuitBreaker, Arc<Mutex<f64>>) {
        fixed_clock_params(2, 60.0, 120.0)
    }

    fn fixed_clock_params(
        threshold: usize,
        window: f64,
        cooldown: f64,
    ) -> (HostCircuitBreaker, Arc<Mutex<f64>>) {
        let t = Arc::new(Mutex::new(1000.0));
        let t2 = t.clone();
        let cb =
            HostCircuitBreaker::with_clock(threshold, window, cooldown, Box::new(move || *t2.lock().unwrap()));
        (cb, t)
    }

    // ---- URL validation golden vectors (from Python urllib.parse) ----

    #[test]
    fn scheme_rejected_non_http() {
        for url in [
            "file:///etc/passwd",
            "file:///etc/hostname",
            "ftp://example.com/file",
            "gopher://example.com/",
            "data:text/plain,hello",
            "javascript:alert(1)",
        ] {
            let err = validate_url(url, URLLIB_ALLOWED_SCHEMES).unwrap_err();
            assert!(err.message.contains("scheme"), "url={url} msg={}", err.message);
        }
        assert_eq!(
            validate_url("file:///etc/passwd", URLLIB_ALLOWED_SCHEMES)
                .unwrap_err()
                .message,
            "Refused URL with scheme 'file': only http/https permitted"
        );
    }

    #[test]
    fn userinfo_rejected() {
        for url in [
            "https://user:pass@example.com/api",
            "https://user@example.com/api",
            "http://admin:secret@example.com/",
            "http://example.com@evil.com/",
            "http://@evil.com/",
            "http://@ftp://hostname/",
            "https://example.com:80@evil.com:443/",
        ] {
            let err = validate_url(url, URLLIB_ALLOWED_SCHEMES).unwrap_err();
            assert!(
                err.message.contains("credentials"),
                "url={url} msg={}",
                err.message
            );
        }
    }

    #[test]
    fn no_host_rejected() {
        let err = validate_url("https:///path-but-no-host", URLLIB_ALLOWED_SCHEMES).unwrap_err();
        assert_eq!(
            err.message,
            "Refused URL with no host: 'https:///path-but-no-host'"
        );
    }

    #[test]
    fn valid_urls_accepted() {
        let ok = validate_url("https://api.example.com/v1/things?q=foo", URLLIB_ALLOWED_SCHEMES)
            .unwrap();
        assert_eq!(ok.scheme, "https");
        assert_eq!(ok.host, "api.example.com");
        validate_url("http://127.0.0.1:8080/health", URLLIB_ALLOWED_SCHEMES).unwrap();
        validate_url("https://api.osv.dev/v1/querybatch", URLLIB_ALLOWED_SCHEMES).unwrap();
    }

    #[test]
    fn egress_https_only() {
        let err = validate_url("http://example.com/api", crate::egress_backend::EGRESS_ALLOWED_SCHEMES)
            .unwrap_err();
        assert_eq!(
            err.message,
            "Refused URL with scheme 'http': only https permitted"
        );
        validate_url("https://example.com/api", crate::egress_backend::EGRESS_ALLOWED_SCHEMES)
            .unwrap();
    }

    #[test]
    fn over_long_url_rejected() {
        let url = format!("https://example.com/{}", "a".repeat(MAX_URL_BYTES));
        let err = validate_url(&url, URLLIB_ALLOWED_SCHEMES).unwrap_err();
        assert!(err.message.contains("byte cap"), "{}", err.message);
    }

    #[test]
    fn urlsplit_fields() {
        let r = urlsplit("http://example.com@evil.com/").unwrap();
        assert_eq!(r.scheme, "http");
        assert_eq!(r.hostname.as_deref(), Some("evil.com"));
        assert_eq!(r.username.as_deref(), Some("example.com"));
        assert_eq!(r.password, None);

        let r = urlsplit("http://@evil.com/").unwrap();
        assert_eq!(r.username.as_deref(), Some(""));
        assert_eq!(r.hostname.as_deref(), Some("evil.com"));

        let r = urlsplit("https://example.com:80@evil.com:443/").unwrap();
        assert_eq!(r.username.as_deref(), Some("example.com"));
        assert_eq!(r.password.as_deref(), Some("80"));
        assert_eq!(r.hostname.as_deref(), Some("evil.com"));

        let r = urlsplit("https:///path-but-no-host").unwrap();
        assert_eq!(r.scheme, "https");
        assert_eq!(r.hostname, None);
    }

    // ---- Retry-After golden vectors (from Python _parse_retry_after) ----

    #[test]
    fn retry_after_seconds() {
        // now fixed so the date-branch clamps are deterministic. Unix ts for
        // roughly 2024-01-01 keeps 2000 in the past and 2030 far in the future.
        let now = 1_704_067_200.0;
        assert_eq!(parse_retry_after_at(Some("5"), now), Some(5));
        assert_eq!(parse_retry_after_at(Some("  10  "), now), Some(10));
        assert_eq!(parse_retry_after_at(Some("0"), now), Some(1));
        assert_eq!(parse_retry_after_at(Some("99999"), now), Some(1800));
        assert_eq!(parse_retry_after_at(Some("-5"), now), Some(1));
        assert_eq!(parse_retry_after_at(Some("+7"), now), Some(7));
        assert_eq!(parse_retry_after_at(Some("1800"), now), Some(1800));
        assert_eq!(parse_retry_after_at(Some("1801"), now), Some(1800));
        assert_eq!(parse_retry_after_at(Some("garbage"), now), None);
        assert_eq!(parse_retry_after_at(None, now), None);
        assert_eq!(parse_retry_after_at(Some(""), now), None);
        assert_eq!(parse_retry_after_at(Some("  "), now), None);
        assert_eq!(parse_retry_after_at(Some("3.5"), now), None);
    }

    #[test]
    fn retry_after_http_date() {
        let now = 1_704_067_200.0; // ~2024-01-01
        assert_eq!(
            parse_retry_after_at(Some("Mon, 01 Jan 2030 00:00:00 GMT"), now),
            Some(1800)
        );
        assert_eq!(
            parse_retry_after_at(Some("Mon, 01 Jan 2000 00:00:00 GMT"), now),
            Some(1)
        );
    }

    #[test]
    fn http_date_epoch_values() {
        // 2000-01-01T00:00:00Z = 946684800; 2030-01-01 = 1893456000.
        assert_eq!(parse_http_date("Mon, 01 Jan 2000 00:00:00 GMT"), Some(946_684_800));
        assert_eq!(parse_http_date("Mon, 01 Jan 2030 00:00:00 GMT"), Some(1_893_456_000));
        // Numeric offset honoured (05:00 -0500 == 10:00 UTC).
        assert_eq!(
            parse_http_date("01 Jan 2000 05:00:00 -0500"),
            Some(946_684_800 + 10 * 3600)
        );
    }

    // ---- proxy 403 classification ----

    #[test]
    fn proxy_forbidden_classification() {
        assert!(is_proxy_forbidden("Tunnel connection failed: 403 Forbidden"));
        assert!(is_proxy_forbidden("HTTP 403"));
        assert!(is_proxy_forbidden("403 Forbidden"));
        assert!(is_proxy_forbidden("response code 403"));
        assert!(is_proxy_forbidden("https://example.com/v1/403/something"));
        assert!(!is_proxy_forbidden("connection refused"));
        assert!(!is_proxy_forbidden("upstream returned 403 (after N retries)"));
        assert!(!is_proxy_forbidden("Cannot connect to proxy."));
    }

    // ---- retry arithmetic ----

    #[test]
    fn transient_classification() {
        assert!(is_transient_status(Some(429)));
        assert!(is_transient_status(Some(500)));
        assert!(is_transient_status(Some(503)));
        assert!(is_transient_status(Some(599)));
        assert!(!is_transient_status(Some(600)));
        assert!(!is_transient_status(Some(400)));
        assert!(!is_transient_status(Some(404)));
        assert!(!is_transient_status(None));
    }

    #[test]
    fn max_attempts() {
        assert_eq!(compute_max_attempts(0), 1);
        assert_eq!(compute_max_attempts(2), 3);
        assert_eq!(compute_max_attempts(3), 4);
        assert_eq!(compute_max_attempts(5), 6);
        assert_eq!(compute_max_attempts(100), 6);
        assert_eq!(compute_max_attempts(-1), 1);
    }

    #[test]
    fn backoff_invariant() {
        assert_eq!(BACKOFF_SECONDS.len(), (crate::DEFAULT_RETRIES as usize) + 1);
        assert_eq!(BACKOFF_SECONDS, [1, 2, 5, 15, 60, 300]);
    }

    // ---- gzip / headers ----

    #[test]
    fn gzip_sniff() {
        assert!(looks_gzip(&[0x1f, 0x8b, 0x08, 0x00]));
        assert!(!looks_gzip(b"{\"a\": 1}"));
        assert!(!looks_gzip(&[0x1f]));
        assert!(!looks_gzip(&[]));
    }

    #[test]
    fn header_collapse() {
        let out = collapse_headers(&[
            ("ETag".into(), "\"v1.2.3\"".into()),
            ("Cache-Control".into(), "max-age=3600".into()),
        ]);
        assert_eq!(
            out,
            vec![
                ("etag".to_string(), "\"v1.2.3\"".to_string()),
                ("cache-control".to_string(), "max-age=3600".to_string()),
            ]
        );

        let out = collapse_headers(&[
            ("Set-Cookie".into(), "a=1".into()),
            ("Set-Cookie".into(), "b=2".into()),
        ]);
        assert_eq!(out, vec![("set-cookie".to_string(), "a=1\nb=2".to_string())]);

        assert_eq!(collapse_headers(&[]), Vec::<(String, String)>::new());
    }

    // ---- circuit breaker golden vectors (from Python _HostCircuitBreaker) ----

    #[test]
    fn fresh_breaker_allows() {
        let (cb, _t) = fixed_clock();
        assert_eq!(cb.is_open("example.com", 443).0, false);
    }

    #[test]
    fn below_threshold_stays_closed() {
        let (cb, _t) = fixed_clock_params(3, 60.0, 120.0);
        cb.record_failure("a.example", 443);
        cb.record_failure("a.example", 443);
        assert_eq!(cb.is_open("a.example", 443).0, false);
    }

    #[test]
    fn at_threshold_opens() {
        let (cb, _t) = fixed_clock_params(2, 60.0, 120.0);
        assert_eq!(cb.record_failure("a.example", 443), false);
        assert_eq!(cb.record_failure("a.example", 443), true);
        let (open, remaining) = cb.is_open("a.example", 443);
        assert!(open);
        assert!(remaining > 0.0 && remaining <= 120.0);
    }

    #[test]
    fn per_host_and_per_port_isolation() {
        let (cb, _t) = fixed_clock_params(2, 60.0, 120.0);
        cb.record_failure("bad.example", 443);
        cb.record_failure("bad.example", 443);
        assert!(cb.is_open("bad.example", 443).0);
        assert!(!cb.is_open("ok.example", 443).0);
        assert!(!cb.is_open("bad.example", 8080).0);
    }

    #[test]
    fn success_resets() {
        let (cb, _t) = fixed_clock_params(2, 60.0, 120.0);
        cb.record_failure("a.example", 443);
        cb.record_failure("a.example", 443);
        assert!(cb.is_open("a.example", 443).0);
        cb.record_success("a.example", 443);
        assert!(!cb.is_open("a.example", 443).0);
        cb.record_failure("a.example", 443);
        assert!(!cb.is_open("a.example", 443).0);
    }

    #[test]
    fn old_failures_drop_out_of_window() {
        let (cb, t) = fixed_clock_params(2, 60.0, 120.0);
        cb.record_failure("a.example", 443);
        *t.lock().unwrap() = 1100.0; // +100s > 60s window
        cb.record_failure("a.example", 443);
        assert!(!cb.is_open("a.example", 443).0);
    }

    #[test]
    fn cooldown_elapses_closes() {
        let (cb, t) = fixed_clock_params(2, 60.0, 120.0);
        cb.record_failure("a.example", 443);
        cb.record_failure("a.example", 443);
        assert!(cb.is_open("a.example", 443).0);
        *t.lock().unwrap() = 1200.0; // +200s > 120s cooldown
        assert!(!cb.is_open("a.example", 443).0);
    }

    #[test]
    fn case_insensitive_host_keying() {
        let (cb, _t) = fixed_clock_params(2, 60.0, 120.0);
        cb.record_failure("Example.com", 443);
        cb.record_failure("EXAMPLE.COM", 443);
        assert!(cb.is_open("example.com", 443).0);
    }
}
