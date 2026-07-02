//! Dataflow corpus metrics — Rust port of the pure core of
//! `core/dataflow/corpus_metrics.py`. Confusion-matrix accumulation,
//! precision/recall/F1, the FP-category breakdown, the human-readable render,
//! and the pivot gate all port here; the CSV read + argparse CLI stay Python.

pub mod corpus_metrics;

pub use corpus_metrics::{check_pivot_gate, compute, render, Metrics, Row};
