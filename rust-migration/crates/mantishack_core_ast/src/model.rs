//! Dataclasses for the per-function AST view — Rust port of `core/ast/model.py`.
//!
//! Schema is frozen + JSON-serialisable so consumers (`/understand --map`,
//! `/audit` annotations) can persist the view alongside their own output
//! without losing precision on round-trip.
//!
//! [`CallSite`] (from `mantishack_core_inventory::call_graph`) is reused verbatim
//! for the calls list — no conversion at the boundary — mirroring the Python
//! re-export `from core.inventory.call_graph import CallSite`.

use serde_json::{Map, Value};

// Re-exported so `core.ast` consumers don't have to know it lives in inventory.
pub use mantishack_core_inventory::call_graph::CallSite;

/// Frozen schema version stamped on every [`FunctionView`].
pub const SCHEMA_VERSION: i64 = 1;

/// One explicit `return` statement in a function body.
///
/// `value_text` is the text of the returned expression (empty string for a bare
/// `return`). Implicit returns (end-of-function fall-through in C/Go, etc.) are
/// NOT emitted — only explicit `return` statements, matching the Python model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Return {
    pub line: i64,
    /// Empty for a bare `return`.
    pub value_text: String,
}

/// Structured view of one function. Mirrors the Python `FunctionView` dataclass.
///
/// The function is identified by `(file, function, lines)`. `has_inline_asm` is
/// true only for C/C++ functions whose body contains a GNU inline-asm construct;
/// it is always false for other languages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionView {
    pub function: String,
    pub file: String,
    pub language: String,
    /// `(start, end)`, 1-indexed inclusive.
    pub lines: (i64, i64),
    pub signature: String,
    pub calls_made: Vec<CallSite>,
    pub returns: Vec<Return>,
    pub has_inline_asm: bool,
    pub schema_version: i64,
}

impl FunctionView {
    /// Serialise for JSON output (`/understand --map`, CLI).
    ///
    /// Shape-identical to the Python `FunctionView.to_dict()`: each call carries
    /// exactly `line`/`chain`/`caller`/`receiver_class` (the inventory
    /// `CallSite`'s extra `receiver_type`/`argument_identifiers` fields are
    /// dropped here, matching the Python model), and each return carries
    /// `line`/`value_text`. `caller`/`receiver_class` are emitted as JSON `null`
    /// when unset (the key is always present).
    pub fn to_json(&self) -> Value {
        let calls: Vec<Value> = self
            .calls_made
            .iter()
            .map(|c| {
                let mut m = Map::new();
                m.insert("line".to_string(), Value::from(c.line));
                m.insert("chain".to_string(), Value::from(c.chain.clone()));
                m.insert(
                    "caller".to_string(),
                    c.caller.clone().map(Value::from).unwrap_or(Value::Null),
                );
                m.insert(
                    "receiver_class".to_string(),
                    c.receiver_class
                        .clone()
                        .map(Value::from)
                        .unwrap_or(Value::Null),
                );
                Value::Object(m)
            })
            .collect();

        let returns: Vec<Value> = self
            .returns
            .iter()
            .map(|r| {
                let mut m = Map::new();
                m.insert("line".to_string(), Value::from(r.line));
                m.insert("value_text".to_string(), Value::from(r.value_text.clone()));
                Value::Object(m)
            })
            .collect();

        let mut root = Map::new();
        root.insert("function".to_string(), Value::from(self.function.clone()));
        root.insert("file".to_string(), Value::from(self.file.clone()));
        root.insert("language".to_string(), Value::from(self.language.clone()));
        root.insert(
            "lines".to_string(),
            Value::from(vec![self.lines.0, self.lines.1]),
        );
        root.insert("signature".to_string(), Value::from(self.signature.clone()));
        root.insert("calls_made".to_string(), Value::Array(calls));
        root.insert("returns".to_string(), Value::Array(returns));
        root.insert(
            "has_inline_asm".to_string(),
            Value::from(self.has_inline_asm),
        );
        root.insert(
            "schema_version".to_string(),
            Value::from(self.schema_version),
        );
        Value::Object(root)
    }
}
