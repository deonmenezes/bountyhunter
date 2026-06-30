//! Call-graph data structures — Rust port of the `FileCallGraph` family in
//! `core/inventory/call_graph.py`.
//!
//! These are the output shape every per-language call-graph extractor produces.
//! The extractors themselves are ported incrementally (tree-sitter-based ones
//! first; the Python branch uses CPython `ast` and waits on a Python-AST
//! strategy). `to_json` mirrors `FileCallGraph.to_dict()` exactly, including its
//! omit-when-empty rules.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

/// One call expression in a file. `chain` is the callee's attribute chain
/// (`foo.bar.baz()` -> `["foo","bar","baz"]`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallSite {
    pub line: i64,
    pub chain: Vec<String>,
    pub caller: Option<String>,
    pub receiver_class: Option<String>,
    pub argument_identifiers: Vec<String>,
    pub receiver_type: Option<String>,
}

/// A `def`/method carrying one or more decorators (each a name/attribute chain).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecoratedFunction {
    pub name: String,
    pub line: i64,
    pub decorators: Vec<Vec<String>>,
}

/// A class definition: bases, depth-1 methods `(name, line)`, and whether the
/// class itself is nested in another class/function.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClassDef {
    pub name: String,
    pub line: i64,
    pub bases: Vec<String>,
    pub methods: Vec<(String, i64)>,
    pub nested: bool,
}

/// All call-graph data for one source file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileCallGraph {
    pub imports: BTreeMap<String, String>,
    pub calls: Vec<CallSite>,
    pub indirection: BTreeSet<String>,
    pub getattr_targets: BTreeSet<String>,
    pub classes: Vec<ClassDef>,
    pub decorated_functions: Vec<DecoratedFunction>,
    pub package_name: Option<String>,
    pub relative_imports: Vec<(i64, String, String, Option<String>)>,
}

impl FileCallGraph {
    /// Serialize to the same shape as `FileCallGraph.to_dict()`. Default-None
    /// call fields and empty `argument_identifiers` are omitted; `indirection`
    /// and `getattr_targets` are sorted; `package_name` is omitted when unset.
    pub fn to_json(&self) -> Value {
        let calls: Vec<Value> = self
            .calls
            .iter()
            .map(|c| {
                let mut entry = json!({ "line": c.line, "chain": c.chain });
                if let Some(caller) = &c.caller {
                    entry["caller"] = json!(caller);
                }
                if let Some(rc) = &c.receiver_class {
                    entry["receiver_class"] = json!(rc);
                }
                if let Some(rt) = &c.receiver_type {
                    entry["receiver_type"] = json!(rt);
                }
                if !c.argument_identifiers.is_empty() {
                    entry["argument_identifiers"] = json!(c.argument_identifiers);
                }
                entry
            })
            .collect();

        let classes: Vec<Value> = self
            .classes
            .iter()
            .map(|k| {
                json!({
                    "name": k.name,
                    "line": k.line,
                    "bases": k.bases,
                    "methods": k.methods.iter().map(|(n, l)| json!([n, l])).collect::<Vec<_>>(),
                    "nested": k.nested,
                })
            })
            .collect();

        let decorated: Vec<Value> = self
            .decorated_functions
            .iter()
            .map(|d| json!({ "name": d.name, "line": d.line, "decorators": d.decorators }))
            .collect();

        let rel: Vec<Value> = self
            .relative_imports
            .iter()
            .map(|(level, m, name, asname)| json!([level, m, name, asname]))
            .collect();

        // BTreeSet already yields sorted order, matching Python's `sorted(...)`.
        let mut out = json!({
            "imports": self.imports,
            "calls": calls,
            "indirection": self.indirection.iter().collect::<Vec<_>>(),
            "getattr_targets": self.getattr_targets.iter().collect::<Vec<_>>(),
            "classes": classes,
            "decorated_functions": decorated,
            "relative_imports": rel,
        });
        if let Some(pkg) = &self.package_name {
            out["package_name"] = json!(pkg);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_json_omits_empty_optionals() {
        let mut g = FileCallGraph::default();
        g.imports.insert("os".to_string(), "os".to_string());
        g.calls.push(CallSite { line: 3, chain: vec!["f".to_string()], ..Default::default() });
        g.calls.push(CallSite {
            line: 5,
            chain: vec!["self".to_string(), "m".to_string()],
            caller: Some("g".to_string()),
            receiver_class: Some("C".to_string()),
            argument_identifiers: vec!["cb".to_string()],
            ..Default::default()
        });
        g.indirection.insert("getattr".to_string());
        g.classes.push(ClassDef {
            name: "C".to_string(),
            line: 1,
            bases: vec!["Base".to_string()],
            methods: vec![("m".to_string(), 2)],
            nested: false,
        });
        let v = g.to_json();
        // Plain call omits the None fields.
        assert_eq!(v["calls"][0], json!({"line": 3, "chain": ["f"]}));
        // Method call carries caller/receiver_class/argument_identifiers.
        assert_eq!(v["calls"][1]["caller"], json!("g"));
        assert_eq!(v["calls"][1]["receiver_class"], json!("C"));
        assert_eq!(v["calls"][1]["argument_identifiers"], json!(["cb"]));
        assert!(v["calls"][1].get("receiver_type").is_none());
        assert_eq!(v["classes"][0]["methods"], json!([["m", 2]]));
        assert_eq!(v["indirection"], json!(["getattr"]));
        // package_name omitted when unset.
        assert!(v.get("package_name").is_none());
    }

    #[test]
    fn package_name_present_when_set() {
        let g = FileCallGraph { package_name: Some("main".to_string()), ..Default::default() };
        assert_eq!(g.to_json()["package_name"], json!("main"));
    }
}
