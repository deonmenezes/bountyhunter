//! Shared report-formatting utilities — Rust port of the pure functions in
//! `core/reporting/formatting.py`. The renderer + console box-drawing +
//! findings-aware layers stay Python for now.

pub mod formatting;

pub use formatting::{format_elapsed, get_display_status, title_case_type, truncate_path};
