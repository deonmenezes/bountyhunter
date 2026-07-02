//! Faithful Rust port of the **pure logic** of the `core/http/` package
//! (`__init__.py`, `urllib_backend.py`, `egress_backend.py`).
//!
//! `core.http` is MANTISHACK's single outbound-HTTP chokepoint. The bulk of it —
//! opening sockets, urllib3 pool/proxy managers, the retry loop's `time.sleep`
//! backoff, response streaming, live gzip decode, and the `core.sandbox.proxy`
//! singleton the egress backend registers hosts with — is genuine network I/O
//! and **stays in Python by design**. There is no network stack to port and none
//! is faked here.
//!
//! What ports is the deterministic, side-effect-free surface those I/O methods
//! depend on, mirrored 1:1 with the Python modules:
//!
//!   * this module ([`__init__.py`]) — the public constants ([`DEFAULT_MAX_BYTES`]
//!     …), the exception hierarchy ([`HttpError`] / [`SizeLimitExceeded`] /
//!     [`NotModified`]), the [`Response`] wrapper with its `requests`-compat
//!     shim (`json` / `status_code` / `content` / `text` / `iter_content` /
//!     `close`), and the backend-selection decision of `default_client`
//!     ([`select_backend`]).
//!   * [`urllib_backend`] — URL validation, the host circuit breaker, Retry-After
//!     parsing, proxy-403 classification, retry arithmetic, gzip sniff, header
//!     collapse.
//!   * [`egress_backend`] — the https-only scheme narrowing and proxy-URL format.
//!
//! The `HttpClient` Protocol, `UrllibClient`, `EgressClient`, `default_client`'s
//! live backend construction, and `_safe_url_for_log` / secret redaction (which
//! depends on the un-ported `core.security.redaction`) all stay Python.

pub mod egress_backend;
pub mod urllib_backend;

// ─────────────────────────── constants ─────────────────────────────────────

/// `DEFAULT_MAX_BYTES` — 50 MiB response cap.
pub const DEFAULT_MAX_BYTES: i64 = 50 * 1024 * 1024;
/// `DEFAULT_TIMEOUT` — per-attempt connect+read timeout (seconds).
pub const DEFAULT_TIMEOUT: i64 = 30;
/// `DEFAULT_TOTAL_TIMEOUT` — whole-call deadline incl. retries (seconds).
pub const DEFAULT_TOTAL_TIMEOUT: i64 = 600;
/// `DEFAULT_RETRIES` — additional attempts after the first.
pub const DEFAULT_RETRIES: i64 = 5;
/// `DEFAULT_USER_AGENT` — fixed at client construction.
pub const DEFAULT_USER_AGENT: &str = "mantishack/0.1 (+https://github.com/gadievron/raptor)";

// ─────────────────────────── error hierarchy ───────────────────────────────

/// Which node of the Python exception hierarchy an [`HttpError`] represents.
/// `HttpError` is the base; `SizeLimitExceeded` and `NotModified` both subclass
/// it (so a Python `except HttpError:` catches all three).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpErrorKind {
    /// Base `HttpError`.
    Http,
    /// `SizeLimitExceeded(HttpError)`.
    SizeLimit,
    /// `NotModified(HttpError)`.
    NotModified,
}

/// Port of `core.http.HttpError` and its subclasses. Carries the same
/// `message` / `status` / `retry_after` payload; the [`kind`](Self::kind)
/// discriminator preserves the subclass identity.
#[derive(Debug, Clone)]
pub struct HttpError {
    pub kind: HttpErrorKind,
    pub message: String,
    pub status: Option<i64>,
    pub retry_after: Option<i64>,
}

impl HttpError {
    /// `HttpError(message, status=None, retry_after=None)`.
    pub fn new(message: String, status: Option<i64>, retry_after: Option<i64>) -> Self {
        HttpError {
            kind: HttpErrorKind::Http,
            message,
            status,
            retry_after,
        }
    }

    /// `HttpError(message)` with no status / retry_after.
    pub fn plain(message: String) -> Self {
        HttpError::new(message, None, None)
    }

    /// `SizeLimitExceeded(message)`.
    pub fn size_limit(message: String) -> Self {
        HttpError {
            kind: HttpErrorKind::SizeLimit,
            message,
            status: None,
            retry_after: None,
        }
    }

    /// `NotModified(message="304 Not Modified")` — status is always 304.
    pub fn not_modified() -> Self {
        Self::not_modified_with("304 Not Modified".to_string())
    }

    /// `NotModified(message)` — status is always 304.
    pub fn not_modified_with(message: String) -> Self {
        HttpError {
            kind: HttpErrorKind::NotModified,
            message,
            status: Some(304),
            retry_after: None,
        }
    }
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for HttpError {}

// ─────────────────────────── Response ──────────────────────────────────────

/// Port of `core.http.Response`. Header keys are stored lower-cased (order
/// preserved). `url` is the final URL after redirects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: i64,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub url: String,
}

impl Response {
    pub fn new(status: i64, headers: Vec<(String, String)>, body: Vec<u8>, url: String) -> Self {
        Response {
            status,
            headers,
            body,
            url,
        }
    }

    /// Case-insensitive header lookup (keys are already lower-cased on storage).
    pub fn header(&self, key: &str) -> Option<&str> {
        let lk = key.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == lk)
            .map(|(_, v)| v.as_str())
    }

    /// `Response.json()` — parse body as UTF-8 JSON. Raises `HttpError`
    /// ("Response is not valid JSON: …") on decode / parse failure.
    pub fn json(&self) -> Result<serde_json::Value, HttpError> {
        let text = std::str::from_utf8(&self.body)
            .map_err(|e| HttpError::plain(format!("Response is not valid JSON: {}", e)))?;
        serde_json::from_str(text)
            .map_err(|e| HttpError::plain(format!("Response is not valid JSON: {}", e)))
    }

    /// `Response.status_code` — alias for `status`.
    pub fn status_code(&self) -> i64 {
        self.status
    }

    /// `Response.content` — alias for `body`.
    pub fn content(&self) -> &[u8] {
        &self.body
    }

    /// `Response.text` — UTF-8 decoded body with `errors="replace"`.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// `Response.iter_content(chunk_size=65536)` — re-chunk the buffered body.
    pub fn iter_content(&self, chunk_size: usize) -> Vec<Vec<u8>> {
        if self.body.is_empty() {
            return Vec::new();
        }
        self.body.chunks(chunk_size).map(|c| c.to_vec()).collect()
    }

    /// `Response.close()` — no-op for the buffered backend.
    pub fn close(&self) {}
}

// ─────────────────────────── backend selection ─────────────────────────────

/// Which concrete backend `default_client` would build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `UrllibClient` — no allowlist.
    Urllib,
    /// `EgressClient` — allowlisted egress via the in-process proxy.
    Egress,
}

impl Backend {
    pub fn name(&self) -> &'static str {
        match self {
            Backend::Urllib => "urllib",
            Backend::Egress => "egress",
        }
    }
}

/// Backend-selection logic of `default_client`: `allowed_hosts is None` →
/// `UrllibClient`; any list (including empty) → `EgressClient`. The live client
/// construction itself is I/O and stays Python.
pub fn select_backend(allowed_hosts: Option<&[String]>) -> Backend {
    if allowed_hosts.is_some() {
        Backend::Egress
    } else {
        Backend::Urllib
    }
}

// ─────────────────────────── PyO3 bindings ─────────────────────────────────

#[cfg(feature = "python")]
#[allow(unexpected_cfgs)] // pyo3 0.22 create_exception! references a `gil-refs` cfg
mod python {
    use pyo3::prelude::*;
    use pyo3::types::{PyBytes, PyDict, PyModule};

    pyo3::create_exception!(
        mantishack_core_http,
        HttpError,
        pyo3::exceptions::PyException,
        "Raised when an HTTP call fails after retries."
    );
    pyo3::create_exception!(
        mantishack_core_http,
        SizeLimitExceeded,
        HttpError,
        "Raised when a response exceeds max_bytes before we finish reading."
    );
    pyo3::create_exception!(
        mantishack_core_http,
        NotModified,
        HttpError,
        "Raised when a server returns 304 Not Modified."
    );

    fn to_pyerr(e: super::HttpError) -> PyErr {
        match e.kind {
            super::HttpErrorKind::SizeLimit => SizeLimitExceeded::new_err(e.message),
            super::HttpErrorKind::NotModified => NotModified::new_err(e.message),
            super::HttpErrorKind::Http => HttpError::new_err(e.message),
        }
    }

    /// `Response` — the `requests`-compat wrapper.
    #[pyclass(name = "Response")]
    struct PyResponse {
        inner: super::Response,
    }

    #[pymethods]
    impl PyResponse {
        #[new]
        #[pyo3(signature = (status, headers, body, url))]
        fn new(status: i64, headers: Vec<(String, String)>, body: Vec<u8>, url: String) -> Self {
            PyResponse {
                inner: super::Response::new(status, headers, body, url),
            }
        }

        #[getter]
        fn status(&self) -> i64 {
            self.inner.status
        }

        #[getter]
        fn headers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
            let d = PyDict::new_bound(py);
            for (k, v) in &self.inner.headers {
                d.set_item(k, v)?;
            }
            Ok(d)
        }

        #[getter]
        fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
            PyBytes::new_bound(py, &self.inner.body)
        }

        #[getter]
        fn url(&self) -> String {
            self.inner.url.clone()
        }

        #[getter]
        fn status_code(&self) -> i64 {
            self.inner.status_code()
        }

        #[getter]
        fn content<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
            PyBytes::new_bound(py, self.inner.content())
        }

        #[getter]
        fn text(&self) -> String {
            self.inner.text()
        }

        fn json(&self, py: Python<'_>) -> PyResult<PyObject> {
            let text = std::str::from_utf8(&self.inner.body).map_err(|e| {
                HttpError::new_err(format!("Response is not valid JSON: {}", e))
            })?;
            let json_mod = PyModule::import_bound(py, "json")?;
            match json_mod.call_method1("loads", (text,)) {
                Ok(v) => Ok(v.into()),
                Err(e) => Err(HttpError::new_err(format!(
                    "Response is not valid JSON: {}",
                    e
                ))),
            }
        }

        #[pyo3(signature = (chunk_size = 65536))]
        fn iter_content<'py>(
            &self,
            py: Python<'py>,
            chunk_size: usize,
        ) -> Vec<Bound<'py, PyBytes>> {
            self.inner
                .iter_content(chunk_size)
                .into_iter()
                .map(|c| PyBytes::new_bound(py, &c))
                .collect()
        }

        fn close(&self) {
            self.inner.close();
        }
    }

    /// `_HostCircuitBreaker` — per-(host, port) rate-limit fail-fast.
    #[pyclass(name = "_HostCircuitBreaker")]
    struct PyCircuitBreaker {
        inner: super::urllib_backend::HostCircuitBreaker,
    }

    #[pymethods]
    impl PyCircuitBreaker {
        #[new]
        #[pyo3(signature = (*, threshold = 2, window = 60.0, cooldown = 120.0))]
        fn new(threshold: usize, window: f64, cooldown: f64) -> Self {
            PyCircuitBreaker {
                inner: super::urllib_backend::HostCircuitBreaker::with_params(
                    threshold, window, cooldown,
                ),
            }
        }

        fn is_open(&self, host: &str, port: i64) -> (bool, f64) {
            self.inner.is_open(host, port)
        }

        fn record_failure(&self, host: &str, port: i64) -> bool {
            self.inner.record_failure(host, port)
        }

        fn record_success(&self, host: &str, port: i64) {
            self.inner.record_success(host, port);
        }
    }

    /// `_validate_url(url, allowed_schemes=["http","https"]) -> (scheme, host)`.
    #[pyfunction]
    #[pyo3(signature = (url, allowed_schemes=None))]
    fn validate_url(url: &str, allowed_schemes: Option<Vec<String>>) -> PyResult<(String, String)> {
        let owned: Vec<String> = allowed_schemes.unwrap_or_else(|| {
            super::urllib_backend::URLLIB_ALLOWED_SCHEMES
                .iter()
                .map(|s| s.to_string())
                .collect()
        });
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        super::urllib_backend::validate_url(url, &refs)
            .map(|v| (v.scheme, v.host))
            .map_err(to_pyerr)
    }

    /// `_parse_retry_after(value) -> int | None`.
    #[pyfunction]
    #[pyo3(signature = (value=None))]
    fn parse_retry_after(value: Option<&str>) -> Option<i64> {
        super::urllib_backend::parse_retry_after(value)
    }

    /// Classify a ProxyError message: True = permanent (off-allowlist 403).
    #[pyfunction]
    fn is_proxy_forbidden(message: &str) -> bool {
        super::urllib_backend::is_proxy_forbidden(message)
    }

    /// Transient-status classification (429 / 5xx).
    #[pyfunction]
    #[pyo3(signature = (status=None))]
    fn is_transient_status(status: Option<i64>) -> bool {
        super::urllib_backend::is_transient_status(status)
    }

    /// `max(1, min(retries + 1, len(_BACKOFF_SECONDS)))`.
    #[pyfunction]
    fn compute_max_attempts(retries: i64) -> usize {
        super::urllib_backend::compute_max_attempts(retries)
    }

    /// gzip magic-byte sniff.
    #[pyfunction]
    fn looks_gzip(data: Vec<u8>) -> bool {
        super::urllib_backend::looks_gzip(&data)
    }

    /// Collapse a header list to the `Response.headers` mapping.
    #[pyfunction]
    fn collapse_headers(entries: Vec<(String, String)>) -> Vec<(String, String)> {
        super::urllib_backend::collapse_headers(&entries)
    }

    /// Backend selection: None → "urllib", any list → "egress".
    #[pyfunction]
    #[pyo3(signature = (allowed_hosts=None))]
    fn select_backend(allowed_hosts: Option<Vec<String>>) -> &'static str {
        super::select_backend(allowed_hosts.as_deref()).name()
    }

    /// `f"http://127.0.0.1:{port}"`.
    #[pyfunction]
    fn egress_proxy_url(port: u16) -> String {
        super::egress_backend::egress_proxy_url(port)
    }

    #[pymodule]
    pub fn mantishack_core_http(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add("DEFAULT_MAX_BYTES", super::DEFAULT_MAX_BYTES)?;
        m.add("DEFAULT_TIMEOUT", super::DEFAULT_TIMEOUT)?;
        m.add("DEFAULT_TOTAL_TIMEOUT", super::DEFAULT_TOTAL_TIMEOUT)?;
        m.add("DEFAULT_RETRIES", super::DEFAULT_RETRIES)?;
        m.add("DEFAULT_USER_AGENT", super::DEFAULT_USER_AGENT)?;

        m.add("HttpError", m.py().get_type_bound::<HttpError>())?;
        m.add("SizeLimitExceeded", m.py().get_type_bound::<SizeLimitExceeded>())?;
        m.add("NotModified", m.py().get_type_bound::<NotModified>())?;

        m.add_class::<PyResponse>()?;
        m.add_class::<PyCircuitBreaker>()?;

        m.add_function(wrap_pyfunction!(validate_url, m)?)?;
        m.add_function(wrap_pyfunction!(parse_retry_after, m)?)?;
        m.add_function(wrap_pyfunction!(is_proxy_forbidden, m)?)?;
        m.add_function(wrap_pyfunction!(is_transient_status, m)?)?;
        m.add_function(wrap_pyfunction!(compute_max_attempts, m)?)?;
        m.add_function(wrap_pyfunction!(looks_gzip, m)?)?;
        m.add_function(wrap_pyfunction!(collapse_headers, m)?)?;
        m.add_function(wrap_pyfunction!(select_backend, m)?)?;
        m.add_function(wrap_pyfunction!(egress_proxy_url, m)?)?;
        Ok(())
    }
}

#[cfg(feature = "python")]
pub use python::mantishack_core_http;

// ─────────────────────────── tests ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(DEFAULT_MAX_BYTES, 52_428_800);
        assert_eq!(DEFAULT_TIMEOUT, 30);
        assert_eq!(DEFAULT_TOTAL_TIMEOUT, 600);
        assert_eq!(DEFAULT_RETRIES, 5);
        assert_eq!(
            DEFAULT_USER_AGENT,
            "mantishack/0.1 (+https://github.com/gadievron/raptor)"
        );
    }

    #[test]
    fn error_hierarchy() {
        let e = HttpError::new("boom".into(), Some(500), Some(12));
        assert_eq!(e.kind, HttpErrorKind::Http);
        assert_eq!(e.status, Some(500));
        assert_eq!(e.retry_after, Some(12));

        let sz = HttpError::size_limit("too big".into());
        assert_eq!(sz.kind, HttpErrorKind::SizeLimit);
        assert_eq!(sz.status, None);

        let nm = HttpError::not_modified();
        assert_eq!(nm.kind, HttpErrorKind::NotModified);
        assert_eq!(nm.status, Some(304));
        assert_eq!(nm.message, "304 Not Modified");
    }

    #[test]
    fn response_shim() {
        let r = Response::new(404, vec![], b"abc".to_vec(), "https://x/".into());
        assert_eq!(r.status_code(), 404);
        assert_eq!(r.content(), b"abc");

        // text: invalid UTF-8 -> replacement char, no panic.
        let r = Response::new(200, vec![], b"hello \xff world".to_vec(), "https://x/".into());
        let t = r.text();
        assert!(t.contains("hello") && t.contains("world"));
    }

    #[test]
    fn response_iter_content() {
        let r = Response::new(200, vec![], b"abcdefghij".to_vec(), "https://x/".into());
        assert_eq!(
            r.iter_content(3),
            vec![
                b"abc".to_vec(),
                b"def".to_vec(),
                b"ghi".to_vec(),
                b"j".to_vec()
            ]
        );
        let empty = Response::new(200, vec![], b"".to_vec(), "https://x/".into());
        assert_eq!(empty.iter_content(65536), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn response_json_ok_and_err() {
        let r = Response::new(200, vec![], b"{\"x\": 42}".to_vec(), "https://x/".into());
        assert_eq!(r.json().unwrap()["x"], serde_json::json!(42));

        let bad = Response::new(200, vec![], b"not json{".to_vec(), "https://x/".into());
        let err = bad.json().unwrap_err();
        assert!(err.message.contains("not valid JSON"), "{}", err.message);
    }

    #[test]
    fn response_header_lookup() {
        let r = Response::new(
            200,
            vec![("etag".into(), "\"v1.2.3\"".into())],
            b"".to_vec(),
            "https://x/".into(),
        );
        assert_eq!(r.header("etag"), Some("\"v1.2.3\""));
        assert_eq!(r.header("ETag"), Some("\"v1.2.3\""));
        assert_eq!(r.header("missing"), None);
    }

    #[test]
    fn backend_selection() {
        assert_eq!(select_backend(None), Backend::Urllib);
        assert_eq!(select_backend(None).name(), "urllib");
        let hosts = vec!["api.osv.dev".to_string()];
        assert_eq!(select_backend(Some(&hosts)), Backend::Egress);
        assert_eq!(select_backend(Some(&hosts)).name(), "egress");
        // Even an empty list selects egress (Python `is not None`).
        let empty: Vec<String> = vec![];
        assert_eq!(select_backend(Some(&empty)), Backend::Egress);
    }
}
