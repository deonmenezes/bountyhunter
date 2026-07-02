//! Faithful Rust port of the **pure logic** in `core/http/egress_backend.py`.
//!
//! `EgressClient` is a thin subclass of `UrllibClient` that routes every request
//! through the in-process HTTPS proxy (`core.sandbox.proxy`). Its behaviour is
//! almost entirely I/O and process-singleton wiring — `get_proxy(...)` host
//! registration, `urllib3.ProxyManager` construction, the shared retry/backoff
//! machinery inherited from `UrllibClient` — all of which **stays in Python by
//! design** (there is no network stack to port, and the `core.sandbox.proxy`
//! singleton is out of scope).
//!
//! The pure surface that ports is:
//!
//!   * [`EGRESS_ALLOWED_SCHEMES`] — the `_ALLOWED_SCHEMES = ("https",)` narrowing
//!     that makes an `http://` URL fail at [`crate::urllib_backend::validate_url`]
//!     with a clear message instead of a confusing late proxy error.
//!   * [`egress_proxy_url`] — the `f"http://127.0.0.1:{proxy.port}"` proxy-URL
//!     formatting used when constructing the `ProxyManager`.
//!   * [`DEFAULT_POOL_MAXSIZE`] — re-exported; the `ProxyManager` uses the same
//!     per-pool `maxsize` as `UrllibClient`.

pub use crate::urllib_backend::DEFAULT_POOL_MAXSIZE;

/// `EgressClient._ALLOWED_SCHEMES` — https only.
pub const EGRESS_ALLOWED_SCHEMES: &[&str] = &["https"];

/// Format the in-process proxy URL from its bound port:
/// `f"http://127.0.0.1:{port}"`.
pub fn egress_proxy_url(port: u16) -> String {
    format!("http://127.0.0.1:{}", port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_url_format() {
        assert_eq!(egress_proxy_url(12345), "http://127.0.0.1:12345");
        assert_eq!(egress_proxy_url(54321), "http://127.0.0.1:54321");
    }

    #[test]
    fn https_only() {
        assert_eq!(EGRESS_ALLOWED_SCHEMES, &["https"]);
    }

    #[test]
    fn pool_maxsize_shared() {
        assert_eq!(DEFAULT_POOL_MAXSIZE, 10);
        assert!(DEFAULT_POOL_MAXSIZE > 1);
    }
}
