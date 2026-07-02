//! Mermaid diagram rendering — Rust port of `packages/diagram/`. The shared
//! sanitizer + the attack-tree index/label helpers port here; the full
//! `generate` renderers + file I/O stay Python for now.

pub mod attack_paths;
pub mod attack_tree;
pub mod context_map;
pub mod findings_summary;
pub mod hypotheses;
pub mod sanitize;

pub use attack_tree::generate as generate_attack_tree;
pub use sanitize::{detect_id_collisions, sanitize, sanitize_id, DEFAULT_MAX_LEN};
