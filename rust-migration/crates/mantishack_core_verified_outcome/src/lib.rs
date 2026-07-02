//! Oracle-polymorphic verified-outcome record — Rust port of the pure model in
//! `core/verified_outcome/types.py`. The adapters / collect / render / retrieval
//! layers stay Python. `timestamp` is carried as an ISO string (the non-string
//! `datetime.now()` default stays a Python concern); a trailing `Z` is
//! normalised to `+00:00` as `datetime.fromisoformat`/`isoformat` would.

pub mod types;

pub use types::{Oracle, OutcomeStatus, VerifiedOutcome};
