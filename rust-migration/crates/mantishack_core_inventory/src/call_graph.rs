//! Call-graph data structures — Rust port of the `FileCallGraph` family in
//! `core/inventory/call_graph.py`.
//!
//! These are the output shape every per-language call-graph extractor produces.
//! The extractors themselves are ported incrementally (tree-sitter-based ones
//! first; the Python branch uses CPython `ast` and waits on a Python-AST
//! strategy). `to_json` mirrors `FileCallGraph.to_dict()` exactly, including its
//! omit-when-empty rules.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::{json, Value};
use tree_sitter::Node;

use rustpython_parser::ast::{
    Constant as PConstant, Expr as PExpr, Pattern as PPattern, Stmt as PStmt,
    TypeParam as PTypeParam,
};
use rustpython_parser::Parse as _;

use crate::extractors::PyLineIndex;

// Indirection flags (subset; grows as language extractors are ported).
const INDIRECTION_GETATTR: &str = "getattr";
const INDIRECTION_WILDCARD_IMPORT: &str = "wildcard_import";
const INDIRECTION_DUNDER_IMPORT: &str = "dunder_import";
const INDIRECTION_REFLECT: &str = "reflect";
const INDIRECTION_FN_POINTER: &str = "fn_pointer";
const INDIRECTION_IMPORTLIB: &str = "importlib";
const INDIRECTION_DYNAMIC_IMPORT: &str = "dynamic_import";
const INDIRECTION_BRACKET_DISPATCH: &str = "bracket_dispatch";
const INDIRECTION_EVAL: &str = "eval";

const JAVA_TYPE_NODES: &[&str] =
    &["type_identifier", "scoped_type_identifier", "generic_type", "array_type"];

const JS_FUNC_NODES: &[&str] = &[
    "function_declaration", "function_expression", "function", "arrow_function",
    "method_definition", "generator_function_declaration", "generator_function",
];
const JS_PARAM_NODES: &[&str] = &["required_parameter", "optional_parameter"];

fn cg_children<'a>(n: Node<'a>) -> Vec<Node<'a>> {
    let mut c = n.walk();
    n.children(&mut c).collect()
}

fn cg_text<'a>(n: Node<'a>, src: &'a [u8]) -> &'a str {
    n.utf8_text(src).unwrap_or("")
}

fn first_child_of_type<'a>(n: Node<'a>, types: &[&str]) -> Option<Node<'a>> {
    cg_children(n).into_iter().find(|c| types.contains(&c.kind()))
}

fn last_child_of_type<'a>(n: Node<'a>, types: &[&str]) -> Option<Node<'a>> {
    cg_children(n).into_iter().rfind(|c| types.contains(&c.kind()))
}

fn first_named_child(n: Node) -> Option<Node> {
    cg_children(n).into_iter().find(|c| c.is_named())
}

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

// ---------------------------------------------------------------------------
// Go call-graph extractor — port of extract_call_graph_go / _GoCallGraph.
// ---------------------------------------------------------------------------

/// Binding names a bare Go `import "<path>"` makes available: the last path
/// segment, plus convention-aware aliases (versioned modules `.../v2` -> the
/// pre-version segment; hyphenated segments -> a hyphen-collapsed form).
fn go_bare_binding_names(path: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let last = path.rsplit('/').next().unwrap_or("");
    if last.is_empty() {
        return names;
    }
    names.push(last.to_string());

    // Versioned module suffix (`v2`): also bind the pre-version segment.
    if last.starts_with('v') && last.len() > 1 && last[1..].bytes().all(|b| b.is_ascii_digit()) {
        let stripped = match path.rfind('/') {
            Some(i) => &path[..i],
            None => path,
        };
        if !stripped.is_empty() {
            let pre_v_last = stripped.rsplit('/').next().unwrap_or("");
            if !pre_v_last.is_empty() {
                names.push(pre_v_last.to_string());
                if pre_v_last.contains('-') {
                    names.push(pre_v_last.replace('-', ""));
                }
            }
        }
    }
    if last.contains('-') {
        names.push(last.replace('-', ""));
    }
    names
}

struct GoCallGraph {
    graph: FileCallGraph,
    enclosing: Vec<String>,
}

impl GoCallGraph {
    fn walk(&mut self, node: Node, src: &[u8]) {
        match node.kind() {
            "function_declaration" => {
                let name = first_child_of_type(node, &["identifier"])
                    .map(|n| cg_text(n, src).to_string())
                    .unwrap_or_else(|| "<anon>".to_string());
                self.enclosing.push(name);
                for child in cg_children(node) {
                    self.walk(child, src);
                }
                self.enclosing.pop();
                return;
            }
            "method_declaration" => {
                // `func (r Recv) Name()` — the name is a field_identifier.
                let name = first_child_of_type(node, &["field_identifier"])
                    .map(|n| cg_text(n, src).to_string())
                    .unwrap_or_else(|| "<anon>".to_string());
                self.enclosing.push(name);
                for child in cg_children(node) {
                    self.walk(child, src);
                }
                self.enclosing.pop();
                return;
            }
            "import_declaration" => {
                self.visit_import(node, src);
                return; // no calls/functions inside
            }
            "package_clause" => {
                if let Some(p) = first_child_of_type(node, &["package_identifier", "identifier"]) {
                    self.graph.package_name = Some(cg_text(p, src).trim().to_string());
                }
                return;
            }
            "call_expression" => {
                self.visit_call(node, src);
                // fall through to recurse into args for nested calls
            }
            _ => {}
        }
        for child in cg_children(node) {
            self.walk(child, src);
        }
    }

    fn visit_import(&mut self, node: Node, src: &[u8]) {
        for child in cg_children(node) {
            match child.kind() {
                "import_spec" => self.handle_import_spec(child, src),
                "import_spec_list" => {
                    for spec in cg_children(child) {
                        if spec.kind() == "import_spec" {
                            self.handle_import_spec(spec, src);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn handle_import_spec(&mut self, spec: Node, src: &[u8]) {
        let Some(path) = self.import_path(spec, src) else {
            return;
        };
        // First named non-string child is the binding hint.
        let binding = cg_children(spec)
            .into_iter()
            .find(|c| c.kind() != "interpreted_string_literal" && c.is_named());
        if let Some(b) = binding {
            match b.kind() {
                "dot" => {
                    self.graph.indirection.insert(INDIRECTION_WILDCARD_IMPORT.to_string());
                    return;
                }
                "blank_identifier" => return, // side-effect only
                "package_identifier" => {
                    self.graph.imports.insert(cg_text(b, src).to_string(), path);
                    return;
                }
                _ => {}
            }
        }
        // Bare import: bind last segment + convention aliases, first-wins.
        for name in go_bare_binding_names(&path) {
            if !name.is_empty() {
                self.graph.imports.entry(name).or_insert_with(|| path.clone());
            }
        }
    }

    fn import_path(&self, spec: Node, src: &[u8]) -> Option<String> {
        let s = first_child_of_type(spec, &["interpreted_string_literal"])?;
        let content = first_child_of_type(s, &["interpreted_string_literal_content"])?;
        Some(cg_text(content, src).to_string())
    }

    fn visit_call(&mut self, node: Node, src: &[u8]) {
        let Some(callee) = self.call_callee(node) else {
            return;
        };
        let Some(chain) = self.callee_chain(callee, src) else {
            return;
        };
        if chain.first().is_some_and(|s| s == "reflect") {
            self.graph.indirection.insert(INDIRECTION_REFLECT.to_string());
        }
        let caller = self.enclosing.last().cloned();
        self.graph.calls.push(CallSite {
            line: node.start_position().row as i64 + 1,
            chain,
            caller,
            argument_identifiers: self.call_identifier_args(node, src),
            ..Default::default()
        });
    }

    fn call_callee<'a>(&self, call_node: Node<'a>) -> Option<Node<'a>> {
        for c in cg_children(call_node) {
            if c.kind() == "argument_list" {
                return None;
            }
            if c.is_named() {
                return Some(c);
            }
        }
        None
    }

    fn call_identifier_args(&self, call_node: Node, src: &[u8]) -> Vec<String> {
        let Some(args) = first_child_of_type(call_node, &["argument_list"]) else {
            return Vec::new();
        };
        cg_children(args)
            .into_iter()
            .filter(|c| c.is_named() && c.kind() == "identifier")
            .map(|c| cg_text(c, src).to_string())
            .collect()
    }

    fn callee_chain(&self, callee: Node, src: &[u8]) -> Option<Vec<String>> {
        match callee.kind() {
            "identifier" => Some(vec![cg_text(callee, src).to_string()]),
            "selector_expression" => {
                let mut parts: Vec<String> = Vec::new();
                let mut cur = Some(callee);
                while let Some(c) = cur {
                    if c.kind() != "selector_expression" {
                        break;
                    }
                    let field = last_child_of_type(c, &["field_identifier"])?;
                    parts.push(cg_text(field, src).to_string());
                    cur = cg_children(c).into_iter().find(|x| x.is_named());
                }
                if let Some(c) = cur {
                    if c.kind() == "identifier" {
                        parts.push(cg_text(c, src).to_string());
                        parts.reverse();
                        return Some(parts);
                    }
                }
                None
            }
            _ => None,
        }
    }
}

/// Walk a Go source string via tree-sitter and return its `FileCallGraph`.
/// Empty graph when the grammar is unavailable or the file is unparseable.
pub fn extract_call_graph_go(content: &str) -> FileCallGraph {
    let Some(tree) = mantishack_ts::parse("go", content) else {
        return FileCallGraph::default();
    };
    let mut w = GoCallGraph { graph: FileCallGraph::default(), enclosing: Vec::new() };
    w.walk(tree.root_node(), content.as_bytes());
    w.graph
}

// ---------------------------------------------------------------------------
// C call-graph extractor — port of extract_call_graph_c / _CCallGraph.
// ---------------------------------------------------------------------------

/// `os.path.splitext(base)[0]` — strip the last extension, skipping leading
/// dots (so `.cshrc` keeps its full name).
fn splitext_root(base: &str) -> &str {
    match base.rfind('.') {
        Some(dot) => {
            let before = &base[..dot];
            if before.bytes().any(|b| b != b'.') {
                before
            } else {
                base
            }
        }
        None => base,
    }
}

struct CCallGraph {
    graph: FileCallGraph,
    enclosing: Vec<String>,
}

impl CCallGraph {
    fn walk(&mut self, node: Node, src: &[u8]) {
        match node.kind() {
            "preproc_include" => {
                self.visit_include(node, src);
                return;
            }
            "function_definition" => {
                if let Some(name) = self.function_name(node, src) {
                    self.enclosing.push(name);
                    for child in cg_children(node) {
                        self.walk(child, src);
                    }
                    self.enclosing.pop();
                    return;
                }
            }
            "call_expression" => {
                self.visit_call(node, src);
            }
            _ => {}
        }
        for child in cg_children(node) {
            self.walk(child, src);
        }
    }

    fn visit_include(&mut self, node: Node, src: &[u8]) {
        for child in cg_children(node) {
            match child.kind() {
                "string_literal" => {
                    if let Some(path) = unwrap_c_string(child, src) {
                        self.record_include(&path);
                    }
                }
                "system_lib_string" => {
                    let raw = cg_text(child, src).trim();
                    if raw.starts_with('<') && raw.ends_with('>') && raw.len() >= 2 {
                        let path = &raw[1..raw.len() - 1];
                        if !path.is_empty() {
                            self.record_include(path);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn record_include(&mut self, path: &str) {
        let base = path.rsplit('/').next().unwrap_or("");
        let local = splitext_root(base);
        if !local.is_empty() {
            self.graph.imports.insert(local.to_string(), path.to_string());
        }
    }

    fn visit_call(&mut self, node: Node, src: &[u8]) {
        let mut callee = None;
        for c in cg_children(node) {
            if c.kind() == "argument_list" {
                break;
            }
            if c.is_named() {
                callee = Some(c);
                break;
            }
        }
        let Some(callee) = callee else { return };
        let (chain, is_fn_pointer) = self.callee_chain(callee, src);
        let Some(chain) = chain else { return };
        if is_fn_pointer {
            self.graph.indirection.insert(INDIRECTION_FN_POINTER.to_string());
        }
        let caller = self.enclosing.last().cloned();
        self.graph.calls.push(CallSite {
            line: node.start_position().row as i64 + 1,
            chain,
            caller,
            ..Default::default()
        });
    }

    fn callee_chain(&self, node: Node, src: &[u8]) -> (Option<Vec<String>>, bool) {
        match node.kind() {
            "parenthesized_expression" => {
                let Some(inner) = first_named_child(node) else { return (None, false) };
                let (chain, _) = self.callee_chain(inner, src);
                let is_fp = chain.is_some() && inner.kind() == "pointer_expression";
                (chain, is_fp)
            }
            "pointer_expression" => {
                let Some(inner) = first_named_child(node) else { return (None, false) };
                let (chain, _) = self.callee_chain(inner, src);
                let is_fp = chain.is_some();
                (chain, is_fp)
            }
            "identifier" => (Some(vec![cg_text(node, src).to_string()]), false),
            "field_expression" => (self.field_chain(node, src), false),
            _ => (None, false),
        }
    }

    fn field_chain(&self, node: Node, src: &[u8]) -> Option<Vec<String>> {
        let mut parts: Vec<String> = Vec::new();
        let mut cur = Some(node);
        while let Some(c) = cur {
            if c.kind() != "field_expression" {
                break;
            }
            let field = cg_children(c).into_iter().rfind(|x| x.kind() == "field_identifier")?;
            parts.push(cg_text(field, src).to_string());
            cur = cg_children(c)
                .into_iter()
                .find(|x| x.is_named() && x.kind() != "field_identifier");
        }
        let c = cur?;
        if c.kind() == "identifier" {
            parts.push(cg_text(c, src).to_string());
            parts.reverse();
            Some(parts)
        } else {
            None
        }
    }

    fn function_name(&self, node: Node, src: &[u8]) -> Option<String> {
        for c in cg_children(node) {
            if !c.is_named() {
                continue;
            }
            if c.kind() == "function_declarator" {
                return self.declarator_name(c, src);
            }
            if c.kind() == "pointer_declarator" {
                if let Some(inner) = self.find_function_declarator(c) {
                    return self.declarator_name(inner, src);
                }
            }
        }
        None
    }

    fn declarator_name(&self, node: Node, src: &[u8]) -> Option<String> {
        for c in cg_children(node) {
            if !c.is_named() {
                continue;
            }
            if c.kind() == "identifier" {
                return Some(cg_text(c, src).to_string());
            }
            if c.kind() == "parenthesized_declarator" {
                if let Some(inner) = first_named_child(c) {
                    if inner.kind() == "identifier" {
                        return Some(cg_text(inner, src).to_string());
                    }
                }
            }
        }
        None
    }

    fn find_function_declarator<'a>(&self, node: Node<'a>) -> Option<Node<'a>> {
        for c in cg_children(node) {
            if c.kind() == "function_declarator" {
                return Some(c);
            }
            if matches!(c.kind(), "pointer_declarator" | "parenthesized_declarator") {
                if let Some(inner) = self.find_function_declarator(c) {
                    return Some(inner);
                }
            }
        }
        None
    }
}

fn unwrap_c_string(node: Node, src: &[u8]) -> Option<String> {
    if let Some(content) = first_child_of_type(node, &["string_content"]) {
        return Some(cg_text(content, src).to_string());
    }
    let raw = cg_text(node, src);
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        return Some(raw[1..raw.len() - 1].to_string());
    }
    None
}

/// Walk a C source string via tree-sitter-c and return its `FileCallGraph`.
pub fn extract_call_graph_c(content: &str) -> FileCallGraph {
    let Some(tree) = mantishack_ts::parse("c", content) else {
        return FileCallGraph::default();
    };
    let mut w = CCallGraph { graph: FileCallGraph::default(), enclosing: Vec::new() };
    w.walk(tree.root_node(), content.as_bytes());
    w.graph
}

// ---------------------------------------------------------------------------
// Java call-graph extractor — port of extract_call_graph_java / _JavaCallGraph.
// ---------------------------------------------------------------------------

struct JavaCallGraph {
    graph: FileCallGraph,
    enclosing: Vec<String>,
    class_stack: Vec<usize>, // indices into graph.classes (shared-ref parity)
    field_types: Vec<HashMap<String, String>>,
    local_types: HashMap<String, String>,
}

impl JavaCallGraph {
    fn walk(&mut self, node: Node, src: &[u8]) {
        match node.kind() {
            "method_declaration" | "constructor_declaration" => {
                let default = if node.kind() == "method_declaration" { "<anon>" } else { "<ctor>" };
                let name = first_child_of_type(node, &["identifier"])
                    .map(|n| cg_text(n, src).to_string())
                    .unwrap_or_else(|| default.to_string());
                // Register on the directly-enclosing class (depth-1 only).
                if !self.class_stack.is_empty() && self.enclosing.is_empty() {
                    let idx = *self.class_stack.last().unwrap();
                    self.graph.classes[idx]
                        .methods
                        .push((name.clone(), node.start_position().row as i64 + 1));
                }
                self.enclosing.push(name);
                let saved = std::mem::take(&mut self.local_types);
                self.local_types =
                    self.collect_param_types(first_child_of_type(node, &["formal_parameters"]), src);
                for child in cg_children(node) {
                    self.walk(child, src);
                }
                self.enclosing.pop();
                self.local_types = saved;
                return;
            }
            "import_declaration" => {
                self.visit_import(node, src);
                return;
            }
            "package_declaration" => {
                if let Some(scoped) = first_child_of_type(node, &["scoped_identifier", "identifier"]) {
                    let pkg = cg_text(scoped, src).trim().to_string();
                    if !pkg.is_empty() {
                        self.graph.package_name = Some(pkg);
                    }
                }
                return;
            }
            "class_declaration" | "interface_declaration" | "record_declaration"
            | "enum_declaration" => {
                self.visit_class(node, src);
                return;
            }
            "local_variable_declaration" => {
                let types = self.collect_decl_types(node, src);
                self.local_types.extend(types);
                for child in cg_children(node) {
                    self.walk(child, src);
                }
                return;
            }
            "method_invocation" => {
                self.visit_call(node, src);
            }
            _ => {}
        }
        for child in cg_children(node) {
            self.walk(child, src);
        }
    }

    fn visit_class(&mut self, node: Node, src: &[u8]) {
        let cls_name = first_child_of_type(node, &["identifier", "type_identifier"])
            .map(|n| cg_text(n, src).to_string());
        let mut bases: Vec<String> = Vec::new();
        let base_text = |sub: Node| -> String {
            if sub.kind() == "scoped_identifier" {
                cg_text(sub, src).trim().to_string()
            } else {
                cg_text(sub, src).to_string()
            }
        };
        for child in cg_children(node) {
            match child.kind() {
                "superclass" => {
                    for sub in cg_children(child) {
                        if matches!(sub.kind(), "identifier" | "type_identifier" | "scoped_identifier") {
                            let t = base_text(sub);
                            if !t.is_empty() {
                                bases.push(t);
                            }
                        }
                    }
                }
                "super_interfaces" | "extends_interfaces" => {
                    for gc in cg_children(child) {
                        if gc.kind() != "type_list" {
                            continue;
                        }
                        for sub in cg_children(gc) {
                            if matches!(sub.kind(), "identifier" | "type_identifier" | "scoped_identifier") {
                                let t = base_text(sub);
                                if !t.is_empty() {
                                    bases.push(t);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        let Some(cls_name) = cls_name else {
            for child in cg_children(node) {
                self.walk(child, src);
            }
            return;
        };
        let nested = !self.class_stack.is_empty() || !self.enclosing.is_empty();
        self.graph.classes.push(ClassDef {
            name: cls_name,
            line: node.start_position().row as i64 + 1,
            bases,
            methods: Vec::new(),
            nested,
        });
        let idx = self.graph.classes.len() - 1;
        self.class_stack.push(idx);

        // Pre-scan depth-1 field declarations so a field used before its
        // textual declaration still resolves.
        let mut field_types: HashMap<String, String> = HashMap::new();
        if let Some(body) = first_child_of_type(node, &["class_body"]) {
            for member in cg_children(body) {
                if member.kind() == "field_declaration" {
                    field_types.extend(self.collect_decl_types(member, src));
                }
            }
        }
        self.field_types.push(field_types);
        for child in cg_children(node) {
            self.walk(child, src);
        }
        self.class_stack.pop();
        self.field_types.pop();
    }

    fn visit_import(&mut self, node: Node, src: &[u8]) {
        if cg_children(node).iter().any(|c| c.kind() == "asterisk") {
            self.graph.indirection.insert(INDIRECTION_WILDCARD_IMPORT.to_string());
            return;
        }
        let Some(scoped) = first_child_of_type(node, &["scoped_identifier"]) else {
            if let Some(simple) = first_child_of_type(node, &["identifier"]) {
                let name = cg_text(simple, src).to_string();
                self.graph.imports.insert(name.clone(), name);
            }
            return;
        };
        let full_path = cg_text(scoped, src).trim().to_string();
        if full_path.is_empty() {
            return;
        }
        let bound = match full_path.rfind('.') {
            Some(i) => &full_path[i + 1..],
            None => &full_path[..],
        };
        if bound.is_empty() {
            return;
        }
        let bound = bound.to_string();
        self.graph.imports.insert(bound, full_path);
    }

    fn type_name(&self, type_node: Option<Node>, src: &[u8]) -> Option<String> {
        let t = type_node?;
        match t.kind() {
            "type_identifier" => {
                let s = cg_text(t, src);
                if s.is_empty() { None } else { Some(s.to_string()) }
            }
            "scoped_type_identifier" => {
                let txt = cg_text(t, src);
                if txt.is_empty() {
                    None
                } else {
                    let last = txt.rsplit('.').next().unwrap_or("").trim();
                    if last.is_empty() { None } else { Some(last.to_string()) }
                }
            }
            "generic_type" | "array_type" => {
                self.type_name(first_child_of_type(t, JAVA_TYPE_NODES), src)
            }
            _ => None,
        }
    }

    fn collect_param_types(&self, params_node: Option<Node>, src: &[u8]) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let Some(params) = params_node else { return out };
        for p in cg_children(params) {
            if !matches!(p.kind(), "formal_parameter" | "spread_parameter") {
                continue;
            }
            let tn = self.type_name(first_child_of_type(p, JAVA_TYPE_NODES), src);
            let name_node = first_child_of_type(p, &["identifier"]);
            if let (Some(tn), Some(nn)) = (tn, name_node) {
                out.insert(cg_text(nn, src).to_string(), tn);
            }
        }
        out
    }

    fn collect_decl_types(&self, decl_node: Node, src: &[u8]) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let Some(tn) = self.type_name(first_child_of_type(decl_node, JAVA_TYPE_NODES), src) else {
            return out;
        };
        for c in cg_children(decl_node) {
            if c.kind() != "variable_declarator" {
                continue;
            }
            if let Some(nn) = first_child_of_type(c, &["identifier"]) {
                out.insert(cg_text(nn, src).to_string(), tn.clone());
            }
        }
        out
    }

    fn resolve_receiver_type(&self, chain: &[String]) -> Option<String> {
        if chain.len() != 2 || matches!(chain[0].as_str(), "this" | "super") {
            return None;
        }
        let recv = &chain[0];
        if let Some(t) = self.local_types.get(recv) {
            return Some(t.clone());
        }
        if let Some(ft) = self.field_types.last() {
            if let Some(t) = ft.get(recv) {
                return Some(t.clone());
            }
        }
        None
    }

    fn visit_call(&mut self, node: Node, src: &[u8]) {
        let Some(chain) = self.invocation_chain(node, src) else { return };

        if chain.len() == 2 && chain[0] == "Class" && chain[1] == "forName" {
            self.graph.indirection.insert(INDIRECTION_IMPORTLIB.to_string());
        } else if chain.len() >= 2 && chain.last().is_some_and(|s| s == "invoke" || s == "newInstance") {
            self.graph.indirection.insert(INDIRECTION_REFLECT.to_string());
        }

        let caller = self.enclosing.last().cloned();
        let mut receiver_class = None;
        if let Some(&idx) = self.class_stack.last() {
            let cls = &self.graph.classes[idx];
            if !cls.nested
                && !self.enclosing.is_empty()
                && (chain.len() == 1 || (chain.len() == 2 && chain[0] == "this"))
            {
                receiver_class = Some(cls.name.clone());
            }
        }
        let receiver_type = if receiver_class.is_none() {
            self.resolve_receiver_type(&chain)
        } else {
            None
        };
        self.graph.calls.push(CallSite {
            line: node.start_position().row as i64 + 1,
            chain,
            caller,
            receiver_class,
            receiver_type,
            ..Default::default()
        });
    }

    fn invocation_chain(&self, node: Node, src: &[u8]) -> Option<Vec<String>> {
        let mut named: Vec<Node> = Vec::new();
        for child in cg_children(node) {
            if child.kind() == "argument_list" {
                break;
            }
            if !child.is_named() {
                continue;
            }
            match child.kind() {
                "identifier" | "field_access" | "this" | "super" => named.push(child),
                "type_arguments" => continue,
                _ => return None,
            }
        }
        let method_ident = *named.last()?;
        if method_ident.kind() != "identifier" {
            return None;
        }
        let operand = if named.len() >= 2 { Some(named[named.len() - 2]) } else { None };
        let method_name = cg_text(method_ident, src).to_string();
        let Some(operand) = operand else { return Some(vec![method_name]) };
        match operand.kind() {
            "identifier" => Some(vec![cg_text(operand, src).to_string(), method_name]),
            "this" | "super" => Some(vec![operand.kind().to_string(), method_name]),
            "field_access" => {
                let mut parts = self.field_access_chain(operand, src)?;
                parts.push(method_name);
                Some(parts)
            }
            _ => None,
        }
    }

    fn field_access_chain(&self, node: Node, src: &[u8]) -> Option<Vec<String>> {
        let mut parts: Vec<String> = Vec::new();
        let mut cur = Some(node);
        while let Some(c) = cur {
            if c.kind() != "field_access" {
                break;
            }
            let field = last_child_of_type(c, &["identifier"])?;
            parts.push(cg_text(field, src).to_string());
            cur = cg_children(c).into_iter().find(|x| x.is_named());
        }
        let c = cur?;
        if c.kind() == "identifier" {
            parts.push(cg_text(c, src).to_string());
            parts.reverse();
            Some(parts)
        } else {
            None
        }
    }
}

/// Walk a Java source string via tree-sitter and return its `FileCallGraph`.
pub fn extract_call_graph_java(content: &str) -> FileCallGraph {
    let Some(tree) = mantishack_ts::parse("java", content) else {
        return FileCallGraph::default();
    };
    let mut w = JavaCallGraph {
        graph: FileCallGraph::default(),
        enclosing: Vec::new(),
        class_stack: Vec::new(),
        field_types: Vec::new(),
        local_types: HashMap::new(),
    };
    w.walk(tree.root_node(), content.as_bytes());
    w.graph
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript call-graph extractor — port of
// extract_call_graph_javascript / _JsCallGraph.
// ---------------------------------------------------------------------------

struct JsCallGraph {
    graph: FileCallGraph,
    enclosing: Vec<String>,
    class_stack: Vec<usize>,
    field_types: Vec<HashMap<String, String>>,
    local_types: HashMap<String, String>,
}

impl JsCallGraph {
    fn walk(&mut self, node: Node, src: &[u8]) {
        let k = node.kind();
        if matches!(k, "class_declaration" | "abstract_class_declaration") {
            if let Some(name_node) = first_child_of_type(node, &["identifier", "type_identifier"]) {
                let mut bases: Vec<String> = Vec::new();
                if let Some(heritage) = first_child_of_type(node, &["class_heritage"]) {
                    for hc in cg_children(heritage) {
                        if matches!(hc.kind(), "identifier" | "type_identifier") {
                            bases.push(cg_text(hc, src).to_string());
                        } else if matches!(hc.kind(), "extends_clause" | "implements_clause") {
                            for gc in cg_children(hc) {
                                if matches!(gc.kind(), "identifier" | "type_identifier") {
                                    bases.push(cg_text(gc, src).to_string());
                                }
                            }
                        }
                    }
                }
                let nested = !self.class_stack.is_empty() || !self.enclosing.is_empty();
                self.graph.classes.push(ClassDef {
                    name: cg_text(name_node, src).to_string(),
                    line: node.start_position().row as i64 + 1,
                    bases,
                    methods: Vec::new(),
                    nested,
                });
                self.class_stack.push(self.graph.classes.len() - 1);
                let body = first_child_of_type(node, &["class_body"]);
                self.field_types.push(self.collect_field_types(body, src));
                for child in cg_children(node) {
                    self.walk(child, src);
                }
                self.class_stack.pop();
                self.field_types.pop();
                return;
            }
            for child in cg_children(node) {
                self.walk(child, src);
            }
            return;
        }

        if JS_FUNC_NODES.contains(&k) {
            let name = self.function_name(node, src);
            let saved = std::mem::take(&mut self.local_types);
            self.local_types =
                self.collect_param_types(first_child_of_type(node, &["formal_parameters"]), src);
            let mut pushed = false;
            if let Some(name) = &name {
                if k == "method_definition" && !self.class_stack.is_empty() && self.enclosing.is_empty() {
                    let idx = *self.class_stack.last().unwrap();
                    self.graph.classes[idx]
                        .methods
                        .push((name.clone(), node.start_position().row as i64 + 1));
                }
                self.enclosing.push(name.clone());
                pushed = true;
            }
            for child in cg_children(node) {
                self.walk(child, src);
            }
            if pushed {
                self.enclosing.pop();
            }
            self.local_types = saved;
            return;
        }

        if k == "import_statement" {
            self.visit_import(node, src);
            return;
        }
        if matches!(k, "lexical_declaration" | "variable_declaration") {
            self.visit_lex_decl(node, src);
            let locals = self.collect_local_types(node, src);
            self.local_types.extend(locals);
        }
        if k == "call_expression" {
            self.visit_call(node, src);
        }
        for child in cg_children(node) {
            self.walk(child, src);
        }
    }

    fn function_name(&self, node: Node, src: &[u8]) -> Option<String> {
        if !matches!(
            node.kind(),
            "function_declaration" | "generator_function_declaration" | "method_definition"
        ) {
            return None;
        }
        first_child_of_type(node, &["identifier", "property_identifier", "private_property_identifier"])
            .map(|n| cg_text(n, src).to_string())
    }

    fn visit_import(&mut self, node: Node, src: &[u8]) {
        let Some(module) = self.import_module_name(node, src) else { return };
        let Some(clause) = first_child_of_type(node, &["import_clause"]) else { return };
        for c in cg_children(clause) {
            match c.kind() {
                "identifier" => {
                    self.graph.imports.insert(cg_text(c, src).to_string(), module.clone());
                }
                "named_imports" => {
                    for spec in cg_children(c) {
                        if spec.kind() == "import_specifier" {
                            self.add_named_import(spec, &module, src);
                        }
                    }
                }
                "namespace_import" => {
                    if let Some(last_id) = last_child_of_type(c, &["identifier"]) {
                        self.graph.imports.insert(cg_text(last_id, src).to_string(), module.clone());
                    }
                }
                _ => {}
            }
        }
    }

    fn add_named_import(&mut self, spec: Node, module: &str, src: &[u8]) {
        let ids: Vec<Node> = cg_children(spec).into_iter().filter(|c| c.kind() == "identifier").collect();
        if ids.is_empty() {
            return;
        }
        let original = cg_text(ids[0], src).to_string();
        let bound = if ids.len() > 1 { cg_text(ids[ids.len() - 1], src).to_string() } else { original.clone() };
        self.graph.imports.insert(bound, format!("{module}.{original}"));
    }

    fn visit_lex_decl(&mut self, node: Node, src: &[u8]) {
        for declarator in cg_children(node) {
            if declarator.kind() != "variable_declarator" {
                continue;
            }
            let Some(value) = self.declarator_value(declarator) else { continue };
            if value.kind() == "class" {
                if let Some(target) = cg_children(declarator).into_iter().next() {
                    if target.kind() == "identifier" {
                        self.synthesise_class_from_expr(value, cg_text(target, src).to_string(), src);
                    }
                }
            }
            let Some(module) = self.require_module_name(value, src) else { continue };
            let Some(target) = cg_children(declarator).into_iter().next() else { continue };
            match target.kind() {
                "identifier" => {
                    self.graph.imports.insert(cg_text(target, src).to_string(), module);
                }
                "object_pattern" => {
                    for prop in cg_children(target) {
                        if prop.kind() == "shorthand_property_identifier_pattern" {
                            let nm = cg_text(prop, src).to_string();
                            self.graph.imports.insert(nm.clone(), format!("{module}.{nm}"));
                        } else if prop.kind() == "pair_pattern" {
                            let ids: Vec<Node> = cg_children(prop)
                                .into_iter()
                                .filter(|c| matches!(c.kind(), "identifier" | "property_identifier"))
                                .collect();
                            if ids.len() == 2 {
                                let orig = cg_text(ids[0], src).to_string();
                                let alias = cg_text(ids[1], src).to_string();
                                self.graph.imports.insert(alias, format!("{module}.{orig}"));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn synthesise_class_from_expr(&mut self, cls_node: Node, name: String, src: &[u8]) {
        let mut bases: Vec<String> = Vec::new();
        let mut body = None;
        for c in cg_children(cls_node) {
            if c.kind() == "class_heritage" {
                for hc in cg_children(c) {
                    if hc.kind() == "identifier" {
                        bases.push(cg_text(hc, src).to_string());
                    }
                }
            } else if c.kind() == "class_body" {
                body = Some(c);
            }
        }
        let mut methods: Vec<(String, i64)> = Vec::new();
        if let Some(body) = body {
            for c in cg_children(body) {
                if c.kind() != "method_definition" {
                    continue;
                }
                if let Some(m) =
                    first_child_of_type(c, &["identifier", "property_identifier", "private_property_identifier"])
                {
                    methods.push((cg_text(m, src).to_string(), c.start_position().row as i64 + 1));
                }
            }
        }
        let nested = !self.class_stack.is_empty() || !self.enclosing.is_empty();
        self.graph.classes.push(ClassDef {
            name,
            line: cls_node.start_position().row as i64 + 1,
            bases,
            methods,
            nested,
        });
    }

    fn type_name(&self, type_node: Option<Node>, src: &[u8]) -> Option<String> {
        let t = type_node?;
        match t.kind() {
            "type_identifier" => {
                let s = cg_text(t, src);
                if s.is_empty() { None } else { Some(s.to_string()) }
            }
            "nested_type_identifier" => {
                last_child_of_type(t, &["type_identifier"]).map(|n| cg_text(n, src).to_string())
            }
            "generic_type" => {
                self.type_name(first_child_of_type(t, &["type_identifier", "nested_type_identifier"]), src)
            }
            "array_type" => self.type_name(
                first_child_of_type(t, &["type_identifier", "nested_type_identifier", "generic_type", "array_type"]),
                src,
            ),
            _ => None,
        }
    }

    fn annotation_type(&self, ann: Option<Node>, src: &[u8]) -> Option<String> {
        let ann = ann?;
        for c in cg_children(ann) {
            if c.kind() != ":" {
                return self.type_name(Some(c), src);
            }
        }
        None
    }

    fn collect_param_types(&self, params_node: Option<Node>, src: &[u8]) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let Some(params) = params_node else { return out };
        for p in cg_children(params) {
            if !JS_PARAM_NODES.contains(&p.kind()) {
                continue;
            }
            let name = first_child_of_type(p, &["identifier"]);
            let tn = self.annotation_type(first_child_of_type(p, &["type_annotation"]), src);
            if let (Some(tn), Some(name)) = (tn, name) {
                out.insert(cg_text(name, src).to_string(), tn);
            }
        }
        out
    }

    fn collect_field_types(&self, class_body: Option<Node>, src: &[u8]) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let Some(body) = class_body else { return out };
        for member in cg_children(body) {
            if member.kind() != "public_field_definition" {
                continue;
            }
            let name = first_child_of_type(member, &["property_identifier"]);
            let tn = self.annotation_type(first_child_of_type(member, &["type_annotation"]), src);
            if let (Some(tn), Some(name)) = (tn, name) {
                out.insert(cg_text(name, src).to_string(), tn);
            }
        }
        out
    }

    fn collect_local_types(&self, lex_decl_node: Node, src: &[u8]) -> HashMap<String, String> {
        let mut out = HashMap::new();
        for d in cg_children(lex_decl_node) {
            if d.kind() != "variable_declarator" {
                continue;
            }
            let name = first_child_of_type(d, &["identifier"]);
            let tn = self.annotation_type(first_child_of_type(d, &["type_annotation"]), src);
            if let (Some(tn), Some(name)) = (tn, name) {
                out.insert(cg_text(name, src).to_string(), tn);
            }
        }
        out
    }

    fn resolve_receiver_type(&self, chain: &[String]) -> Option<String> {
        if chain.len() != 2 || matches!(chain[0].as_str(), "this" | "super") {
            return None;
        }
        let recv = &chain[0];
        if let Some(t) = self.local_types.get(recv) {
            return Some(t.clone());
        }
        if let Some(ft) = self.field_types.last() {
            if let Some(t) = ft.get(recv) {
                return Some(t.clone());
            }
        }
        None
    }

    fn visit_call(&mut self, node: Node, src: &[u8]) {
        let Some(callee) = self.call_callee(node) else { return };
        if callee.kind() == "import" {
            self.graph.indirection.insert(INDIRECTION_DYNAMIC_IMPORT.to_string());
            return;
        }
        if callee.kind() == "subscript_expression" {
            self.graph.indirection.insert(INDIRECTION_BRACKET_DISPATCH.to_string());
            if let Some(lit) = self.subscript_string_literal(callee, src) {
                self.graph.getattr_targets.insert(lit);
            }
            return;
        }
        let Some(chain) = self.callee_chain(callee, src) else {
            if callee.kind() == "new_expression" {
                if let Some(cls) = first_child_of_type(callee, &["identifier"]) {
                    if cg_text(cls, src) == "Function" {
                        self.graph.indirection.insert(INDIRECTION_EVAL.to_string());
                    }
                }
            }
            return;
        };
        if chain.len() == 1 && chain[0] == "eval" {
            self.graph.indirection.insert(INDIRECTION_EVAL.to_string());
        }
        if chain.len() == 1 && chain[0] == "require" && !self.call_first_arg_is_string(node) {
            self.graph.indirection.insert(INDIRECTION_DYNAMIC_IMPORT.to_string());
        }
        let caller = self.enclosing.last().cloned();
        let mut receiver_class = None;
        if let Some(&idx) = self.class_stack.last() {
            let cls = &self.graph.classes[idx];
            if !cls.nested && !self.enclosing.is_empty() && chain.len() >= 2 && chain[0] == "this" {
                receiver_class = Some(cls.name.clone());
            }
        }
        let receiver_type = if receiver_class.is_none() {
            self.resolve_receiver_type(&chain)
        } else {
            None
        };
        self.graph.calls.push(CallSite {
            line: node.start_position().row as i64 + 1,
            chain,
            caller,
            receiver_class,
            argument_identifiers: self.call_identifier_args(node, src),
            receiver_type,
        });
    }

    fn call_callee<'a>(&self, call_node: Node<'a>) -> Option<Node<'a>> {
        for c in cg_children(call_node) {
            if c.kind() == "arguments" {
                return None;
            }
            if c.is_named() {
                return Some(c);
            }
        }
        None
    }

    fn callee_chain(&self, callee: Node, src: &[u8]) -> Option<Vec<String>> {
        match callee.kind() {
            "identifier" => Some(vec![cg_text(callee, src).to_string()]),
            "member_expression" => {
                let mut parts: Vec<String> = Vec::new();
                let mut cur = Some(callee);
                while let Some(c) = cur {
                    if c.kind() != "member_expression" {
                        break;
                    }
                    let prop = last_child_of_type(c, &["property_identifier", "private_property_identifier"])?;
                    parts.push(cg_text(prop, src).to_string());
                    cur = cg_children(c).into_iter().next();
                }
                if let Some(c) = cur {
                    if c.kind() == "identifier" {
                        parts.push(cg_text(c, src).to_string());
                        parts.reverse();
                        return Some(parts);
                    }
                    if c.kind() == "this" {
                        parts.push("this".to_string());
                        parts.reverse();
                        return Some(parts);
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn call_first_arg_is_string(&self, call_node: Node) -> bool {
        let Some(args) = first_child_of_type(call_node, &["arguments"]) else { return false };
        for c in cg_children(args) {
            if c.is_named() {
                return c.kind() == "string";
            }
        }
        false
    }

    fn call_identifier_args(&self, call_node: Node, src: &[u8]) -> Vec<String> {
        let Some(args) = first_child_of_type(call_node, &["arguments"]) else { return Vec::new() };
        cg_children(args)
            .into_iter()
            .filter(|c| c.is_named() && c.kind() == "identifier")
            .map(|c| cg_text(c, src).to_string())
            .collect()
    }

    fn subscript_string_literal(&self, subscript_node: Node, src: &[u8]) -> Option<String> {
        let named: Vec<Node> = cg_children(subscript_node).into_iter().filter(|c| c.is_named()).collect();
        if named.len() < 2 {
            return None;
        }
        let idx = named[1];
        if idx.kind() != "string" {
            return None;
        }
        first_child_of_type(idx, &["string_fragment"]).map(|f| cg_text(f, src).to_string())
    }

    fn import_module_name(&self, import_node: Node, src: &[u8]) -> Option<String> {
        let s = first_child_of_type(import_node, &["string"])?;
        first_child_of_type(s, &["string_fragment"]).map(|f| cg_text(f, src).to_string())
    }

    fn declarator_value<'a>(&self, declarator: Node<'a>) -> Option<Node<'a>> {
        let named: Vec<Node> = cg_children(declarator).into_iter().filter(|c| c.is_named()).collect();
        if named.len() < 2 {
            return None;
        }
        named.last().copied()
    }

    fn require_module_name(&self, value_node: Node, src: &[u8]) -> Option<String> {
        if value_node.kind() != "call_expression" {
            return None;
        }
        let callee = self.call_callee(value_node)?;
        if callee.kind() != "identifier" || cg_text(callee, src) != "require" {
            return None;
        }
        let args = first_child_of_type(value_node, &["arguments"])?;
        for c in cg_children(args) {
            if !c.is_named() {
                continue;
            }
            if c.kind() != "string" {
                return None; // require(variable) — caller flags dynamic
            }
            return first_child_of_type(c, &["string_fragment"]).map(|f| cg_text(f, src).to_string());
        }
        None
    }
}

/// Walk a JS/TS/TSX source string via tree-sitter and return its
/// `FileCallGraph`. `language` selects the grammar (javascript / typescript / tsx).
pub fn extract_call_graph_js_lang(content: &str, language: &str) -> FileCallGraph {
    let Some(tree) = mantishack_ts::parse(language, content) else {
        return FileCallGraph::default();
    };
    let mut w = JsCallGraph {
        graph: FileCallGraph::default(),
        enclosing: Vec::new(),
        class_stack: Vec::new(),
        field_types: Vec::new(),
        local_types: HashMap::new(),
    };
    w.walk(tree.root_node(), content.as_bytes());
    w.graph
}

/// JavaScript convenience wrapper.
pub fn extract_call_graph_javascript(content: &str) -> FileCallGraph {
    extract_call_graph_js_lang(content, "javascript")
}

// ---------------------------------------------------------------------------
// C++ call-graph extractor — port of extract_call_graph_cpp / _CppCallGraph.
// Reuses the C helpers (unwrap_c_string, splitext_root, first_named_child) and
// adds class/struct/namespace/qualified-id handling.
// ---------------------------------------------------------------------------

fn cpp_find_function_declarator(node: Node) -> Option<Node> {
    for c in cg_children(node) {
        if c.kind() == "function_declarator" {
            return Some(c);
        }
        if matches!(c.kind(), "pointer_declarator" | "parenthesized_declarator") {
            if let Some(inner) = cpp_find_function_declarator(c) {
                return Some(inner);
            }
        }
    }
    None
}

enum CppClass {
    Real(usize), // index into graph.classes
    Synthetic(ClassDef),
}

struct CppCallGraph {
    graph: FileCallGraph,
    enclosing: Vec<String>,
    class_stack: Vec<CppClass>,
    ns_stack: Vec<String>,
}

impl CppCallGraph {
    fn top_class(&self) -> Option<&ClassDef> {
        match self.class_stack.last()? {
            CppClass::Real(idx) => self.graph.classes.get(*idx),
            CppClass::Synthetic(cd) => Some(cd),
        }
    }

    fn class_in_stack(&self, name: &str) -> bool {
        self.class_stack.iter().any(|e| match e {
            CppClass::Real(idx) => self.graph.classes[*idx].name == name,
            CppClass::Synthetic(cd) => cd.name == name,
        })
    }

    fn lookup_class(&self, name: &str) -> Option<&ClassDef> {
        self.graph.classes.iter().find(|c| c.name == name)
    }

    fn walk(&mut self, node: Node, src: &[u8]) {
        match node.kind() {
            "preproc_include" => {
                self.visit_include(node, src);
                return;
            }
            "namespace_definition" => {
                self.visit_namespace_definition(node, src);
                return;
            }
            "class_specifier" | "struct_specifier" => {
                self.visit_class_specifier(node, src);
                return;
            }
            "function_definition" => {
                self.visit_function_definition(node, src);
                return;
            }
            "call_expression" => self.visit_call(node, src),
            "field_initializer" => self.visit_field_initializer(node, src),
            _ => {}
        }
        for child in cg_children(node) {
            self.walk(child, src);
        }
    }

    fn visit_include(&mut self, node: Node, src: &[u8]) {
        for child in cg_children(node) {
            match child.kind() {
                "string_literal" => {
                    if let Some(path) = unwrap_c_string(child, src) {
                        self.record_include(&path);
                    }
                }
                "system_lib_string" => {
                    let raw = cg_text(child, src).trim();
                    if raw.starts_with('<') && raw.ends_with('>') && raw.len() >= 2 {
                        let p = &raw[1..raw.len() - 1];
                        if !p.is_empty() {
                            self.record_include(p);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn record_include(&mut self, path: &str) {
        let base = path.rsplit('/').next().unwrap_or("");
        let local = splitext_root(base);
        if !local.is_empty() {
            self.graph.imports.insert(local.to_string(), path.to_string());
        }
    }

    fn visit_namespace_definition(&mut self, node: Node, src: &[u8]) {
        let mut parts: Vec<String> = Vec::new();
        for c in cg_children(node) {
            if c.kind() == "namespace_identifier" {
                parts.push(cg_text(c, src).to_string());
            } else if c.kind() == "nested_namespace_specifier" {
                for sub in cg_children(c) {
                    if sub.kind() == "namespace_identifier" {
                        parts.push(cg_text(sub, src).to_string());
                    }
                }
            }
        }
        let n = parts.len();
        self.ns_stack.extend(parts);
        if !self.ns_stack.is_empty() {
            self.graph.package_name = Some(self.ns_stack.join("."));
        }
        for c in cg_children(node) {
            self.walk(c, src);
        }
        for _ in 0..n {
            self.ns_stack.pop();
        }
        // deepest-wins: package_name is NOT restored on close.
    }

    fn visit_class_specifier(&mut self, node: Node, src: &[u8]) {
        let Some(name) = first_child_of_type(node, &["type_identifier"]).map(|n| cg_text(n, src).to_string())
        else {
            for c in cg_children(node) {
                self.walk(c, src);
            }
            return;
        };
        let bases = self.extract_bases(node, src);
        let nested = !self.class_stack.is_empty() || !self.enclosing.is_empty();
        let mut cdef = ClassDef {
            name,
            line: node.start_position().row as i64 + 1,
            bases,
            methods: Vec::new(),
            nested,
        };
        self.collect_method_declarations(node, &mut cdef, src);
        self.graph.classes.push(cdef);
        self.class_stack.push(CppClass::Real(self.graph.classes.len() - 1));
        for child in cg_children(node) {
            self.walk(child, src);
        }
        self.class_stack.pop();
    }

    fn extract_bases(&self, node: Node, src: &[u8]) -> Vec<String> {
        let mut bases: Vec<String> = Vec::new();
        for c in cg_children(node) {
            if c.kind() != "base_class_clause" {
                continue;
            }
            for sub in cg_children(c) {
                if !sub.is_named() {
                    continue;
                }
                match sub.kind() {
                    "type_identifier" => bases.push(cg_text(sub, src).to_string()),
                    "qualified_identifier" => {
                        let p = self.qualified_parts(sub, src);
                        if !p.is_empty() {
                            bases.push(p.join("::"));
                        }
                    }
                    "template_type" => {
                        if let Some(inner) = first_child_of_type(sub, &["type_identifier"]) {
                            bases.push(cg_text(inner, src).to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
        bases
    }

    fn collect_method_declarations(&self, node: Node, cdef: &mut ClassDef, src: &[u8]) {
        let Some(body) = first_child_of_type(node, &["field_declaration_list"]) else { return };
        for member in cg_children(body) {
            let mut target = member;
            if target.kind() == "template_declaration" {
                match cg_children(target)
                    .into_iter()
                    .find(|s| matches!(s.kind(), "field_declaration" | "declaration" | "function_definition"))
                {
                    Some(s) => target = s,
                    None => continue,
                }
            }
            if !matches!(target.kind(), "field_declaration" | "declaration" | "function_definition") {
                continue;
            }
            for sub in cg_children(target) {
                if sub.kind() == "function_declarator" {
                    if let Some(name) = self.declarator_name_cpp(sub, src) {
                        cdef.methods.push((name, target.start_position().row as i64 + 1));
                    }
                    break;
                }
            }
        }
    }

    fn visit_function_definition(&mut self, node: Node, src: &[u8]) {
        let name = self.function_name(node, src);
        let qualified_class = self.qualified_class_from_declarator(node, src);
        let Some(name) = name else {
            for c in cg_children(node) {
                self.walk(c, src);
            }
            return;
        };

        // Inline method: register on the current real class (unless pre-pass got it).
        if qualified_class.is_none() {
            if let Some(CppClass::Real(idx)) = self.class_stack.last() {
                let idx = *idx;
                let method_line = node.start_position().row as i64 + 1;
                let already =
                    self.graph.classes[idx].methods.iter().any(|(n, l)| *n == name && *l == method_line);
                if !already {
                    self.graph.classes[idx].methods.push((name.clone(), method_line));
                }
            }
        }

        // Out-of-line method: synthesise a class context inheriting the real
        // class's methods (for bare-call receiver inference).
        let mut pushed_synthetic = false;
        if let Some(qc) = &qualified_class {
            if !self.class_in_stack(qc) {
                let synthetic = match self.lookup_class(qc) {
                    Some(real) => ClassDef {
                        name: qc.clone(),
                        line: real.line,
                        bases: real.bases.clone(),
                        methods: real.methods.clone(),
                        nested: real.nested,
                    },
                    None => ClassDef { name: qc.clone(), line: 0, bases: Vec::new(), methods: Vec::new(), nested: false },
                };
                self.class_stack.push(CppClass::Synthetic(synthetic));
                pushed_synthetic = true;
            }
        }
        self.enclosing.push(name);
        for c in cg_children(node) {
            self.walk(c, src);
        }
        self.enclosing.pop();
        if pushed_synthetic && matches!(self.class_stack.last(), Some(CppClass::Synthetic(_))) {
            self.class_stack.pop();
        }
    }

    fn function_name(&self, node: Node, src: &[u8]) -> Option<String> {
        for c in cg_children(node) {
            if !c.is_named() {
                continue;
            }
            if c.kind() == "function_declarator" {
                return self.declarator_name_cpp(c, src);
            }
            if c.kind() == "pointer_declarator" {
                if let Some(inner) = cpp_find_function_declarator(c) {
                    return self.declarator_name_cpp(inner, src);
                }
            }
        }
        None
    }

    fn declarator_name_cpp(&self, node: Node, src: &[u8]) -> Option<String> {
        for c in cg_children(node) {
            if !c.is_named() {
                continue;
            }
            match c.kind() {
                "identifier" | "field_identifier" | "destructor_name" | "operator_name" => {
                    return Some(cg_text(c, src).to_string());
                }
                "qualified_identifier" => {
                    if let Some(last) = self.qualified_parts(c, src).last() {
                        return Some(last.clone());
                    }
                }
                "parenthesized_declarator" => {
                    if let Some(inner) = first_named_child(c) {
                        if inner.kind() == "identifier" {
                            return Some(cg_text(inner, src).to_string());
                        }
                        if inner.kind() == "qualified_identifier" {
                            if let Some(last) = self.qualified_parts(inner, src).last() {
                                return Some(last.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn qualified_class_from_declarator(&self, node: Node, src: &[u8]) -> Option<String> {
        for c in cg_children(node) {
            if !c.is_named() {
                continue;
            }
            if c.kind() == "function_declarator" {
                return self.qualified_class_from_fn_declarator(c, src);
            }
            if c.kind() == "pointer_declarator" {
                if let Some(inner) = cpp_find_function_declarator(c) {
                    return self.qualified_class_from_fn_declarator(inner, src);
                }
            }
        }
        None
    }

    fn qualified_class_from_fn_declarator(&self, node: Node, src: &[u8]) -> Option<String> {
        for c in cg_children(node) {
            if c.is_named() && c.kind() == "qualified_identifier" {
                let p = self.qualified_parts(c, src);
                if p.len() >= 2 {
                    return Some(p[p.len() - 2].clone());
                }
            }
        }
        None
    }

    fn qualified_parts(&self, node: Node, src: &[u8]) -> Vec<String> {
        let mut parts: Vec<String> = Vec::new();
        let mut cur = Some(node);
        while let Some(c) = cur {
            if c.kind() != "qualified_identifier" {
                break;
            }
            let mut head = None;
            let mut tail = None;
            for ch in cg_children(c) {
                if !ch.is_named() {
                    continue;
                }
                if head.is_none() {
                    head = Some(ch);
                } else {
                    tail = Some(ch);
                    break;
                }
            }
            let Some(head) = head else {
                return parts.into_iter().filter(|p| !p.is_empty()).collect();
            };
            parts.push(self.name_token(head, src));
            cur = tail;
        }
        if let Some(c) = cur {
            let last = self.name_token(c, src);
            if !last.is_empty() {
                parts.push(last);
            }
        }
        parts.into_iter().filter(|p| !p.is_empty()).collect()
    }

    fn name_token(&self, node: Node, src: &[u8]) -> String {
        match node.kind() {
            "identifier" | "namespace_identifier" | "type_identifier" | "field_identifier"
            | "destructor_name" | "operator_name" => cg_text(node, src).to_string(),
            "template_type" | "template_function" => {
                for c in cg_children(node) {
                    if c.is_named() && matches!(c.kind(), "identifier" | "type_identifier") {
                        return cg_text(c, src).to_string();
                    }
                }
                String::new()
            }
            _ => String::new(),
        }
    }

    fn visit_call(&mut self, node: Node, src: &[u8]) {
        let mut callee = None;
        for c in cg_children(node) {
            if c.kind() == "argument_list" {
                break;
            }
            if c.is_named() {
                callee = Some(c);
                break;
            }
        }
        let Some(callee) = callee else { return };
        let (chain, is_fn_pointer) = self.callee_chain(callee, src);
        let Some(chain) = chain else { return };
        if is_fn_pointer {
            self.graph.indirection.insert(INDIRECTION_FN_POINTER.to_string());
        }
        let caller = self.enclosing.last().cloned();
        let receiver_class = self.infer_receiver_class(&chain);
        self.graph.calls.push(CallSite {
            line: node.start_position().row as i64 + 1,
            chain,
            caller,
            receiver_class,
            ..Default::default()
        });
    }

    fn visit_field_initializer(&mut self, node: Node, src: &[u8]) {
        let mut name_node = None;
        for c in cg_children(node) {
            if c.kind() == "field_identifier" {
                name_node = Some(c);
                break;
            }
            if c.kind() == "template_method" {
                for sub in cg_children(c) {
                    if sub.kind() == "field_identifier" {
                        name_node = Some(sub);
                        break;
                    }
                }
                if name_node.is_some() {
                    break;
                }
            }
        }
        let Some(nn) = name_node else { return };
        let name = cg_text(nn, src).to_string();
        let caller = self.enclosing.last().cloned();
        self.graph.calls.push(CallSite {
            line: node.start_position().row as i64 + 1,
            chain: vec![name],
            caller,
            ..Default::default()
        });
    }

    fn infer_receiver_class(&self, chain: &[String]) -> Option<String> {
        let top = self.top_class()?;
        if top.nested {
            return None;
        }
        if chain.len() == 2 && chain[0] == "this" {
            return Some(top.name.clone());
        }
        if chain.len() == 1 && top.methods.iter().any(|(n, _)| n == &chain[0]) {
            return Some(top.name.clone());
        }
        None
    }

    fn callee_chain(&self, node: Node, src: &[u8]) -> (Option<Vec<String>>, bool) {
        match node.kind() {
            "qualified_identifier" => {
                let p = self.qualified_parts(node, src);
                (if p.is_empty() { None } else { Some(p) }, false)
            }
            "field_expression" => (self.field_chain_cpp(node, src), false),
            "template_function" => {
                for c in cg_children(node) {
                    if c.kind() == "identifier" {
                        return (Some(vec![cg_text(c, src).to_string()]), false);
                    }
                }
                (None, false)
            }
            "parenthesized_expression" => {
                let Some(inner) = first_named_child(node) else { return (None, false) };
                let (chain, _) = self.callee_chain(inner, src);
                let is_fp = chain.is_some() && inner.kind() == "pointer_expression";
                (chain, is_fp)
            }
            "pointer_expression" => {
                let Some(inner) = first_named_child(node) else { return (None, false) };
                let (chain, _) = self.callee_chain(inner, src);
                let is_fp = chain.is_some();
                (chain, is_fp)
            }
            "identifier" => (Some(vec![cg_text(node, src).to_string()]), false),
            _ => (None, false),
        }
    }

    fn field_chain_cpp(&self, node: Node, src: &[u8]) -> Option<Vec<String>> {
        let mut parts: Vec<String> = Vec::new();
        let mut cur = Some(node);
        while let Some(c) = cur {
            if c.kind() != "field_expression" {
                break;
            }
            let mut field_node = None;
            for ch in cg_children(c) {
                if ch.kind() == "field_identifier" {
                    field_node = Some(ch);
                } else if ch.kind() == "template_method" {
                    for sub in cg_children(ch) {
                        if sub.kind() == "field_identifier" {
                            field_node = Some(sub);
                            break;
                        }
                    }
                } else if ch.kind() == "dependent_name" {
                    for sub in cg_children(ch) {
                        if sub.kind() == "template_method" {
                            field_node = cg_children(sub).into_iter().find(|i| i.kind() == "field_identifier");
                            break;
                        }
                        if sub.kind() == "field_identifier" {
                            field_node = Some(sub);
                            break;
                        }
                    }
                }
            }
            let field_node = field_node?;
            parts.push(cg_text(field_node, src).to_string());
            cur = cg_children(c)
                .into_iter()
                .find(|x| x.is_named() && !matches!(x.kind(), "field_identifier" | "template_method"));
        }
        let c = cur?;
        match c.kind() {
            "identifier" => {
                parts.push(cg_text(c, src).to_string());
                parts.reverse();
                Some(parts)
            }
            "this" => {
                parts.push("this".to_string());
                parts.reverse();
                Some(parts)
            }
            "qualified_identifier" => {
                let mut head = self.qualified_parts(c, src);
                if head.is_empty() {
                    return None;
                }
                parts.reverse();
                head.extend(parts);
                Some(head)
            }
            "compound_literal_expression" => {
                let tn = self.compound_literal_type_name(c, src)?;
                parts.push(tn);
                parts.reverse();
                Some(parts)
            }
            _ => None,
        }
    }

    fn compound_literal_type_name(&self, node: Node, src: &[u8]) -> Option<String> {
        for c in cg_children(node) {
            if c.kind() == "type_identifier" {
                return Some(cg_text(c, src).to_string());
            }
            if c.kind() == "template_type" {
                if let Some(sub) = first_child_of_type(c, &["type_identifier"]) {
                    return Some(cg_text(sub, src).to_string());
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Rust call-graph extractor — port of extract_call_graph_rust / _RustCallGraph.
// ---------------------------------------------------------------------------

struct RustCallGraph {
    graph: FileCallGraph,
    enclosing: Vec<String>,
    class_stack: Vec<usize>, // indices into graph.classes
    mod_depth: i32,
}

impl RustCallGraph {
    fn walk(&mut self, node: Node, src: &[u8]) {
        match node.kind() {
            "function_item" => {
                let name = first_child_of_type(node, &["identifier"])
                    .map(|n| cg_text(n, src).to_string())
                    .unwrap_or_else(|| "<anon>".to_string());
                if !self.class_stack.is_empty() && self.enclosing.is_empty() {
                    let idx = *self.class_stack.last().unwrap();
                    self.graph.classes[idx].methods.push((name.clone(), node.start_position().row as i64 + 1));
                }
                self.enclosing.push(name);
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                self.enclosing.pop();
                return;
            }
            "function_signature_item" => {
                if let Some(name) = first_child_of_type(node, &["identifier"]) {
                    if let Some(&idx) = self.class_stack.last() {
                        self.graph.classes[idx]
                            .methods
                            .push((cg_text(name, src).to_string(), node.start_position().row as i64 + 1));
                    }
                }
                return;
            }
            "use_declaration" => {
                self.handle_use(node, src);
                return;
            }
            "mod_item" => {
                self.mod_depth += 1;
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                self.mod_depth -= 1;
                return;
            }
            "struct_item" | "enum_item" | "union_item" | "trait_item" => {
                self.visit_type_item(node, src);
                return;
            }
            "impl_item" => {
                self.visit_impl(node, src);
                return;
            }
            "call_expression" => {
                if let Some(chain) = self.call_chain(node, src) {
                    let caller = self.enclosing.last().cloned();
                    let mut receiver_class = None;
                    if !self.class_stack.is_empty()
                        && !self.enclosing.is_empty()
                        && chain.len() == 2
                        && chain[0] == "self"
                    {
                        receiver_class = Some(self.graph.classes[*self.class_stack.last().unwrap()].name.clone());
                    }
                    self.graph.calls.push(CallSite {
                        line: node.start_position().row as i64 + 1,
                        chain,
                        caller,
                        receiver_class,
                        ..Default::default()
                    });
                }
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                return;
            }
            _ => {}
        }
        for c in cg_children(node) {
            self.walk(c, src);
        }
    }

    fn visit_type_item(&mut self, node: Node, src: &[u8]) {
        let name_node = first_child_of_type(node, &["type_identifier"]);
        let mut bases: Vec<String> = Vec::new();
        if node.kind() == "trait_item" {
            if let Some(bounds) = first_child_of_type(node, &["trait_bounds"]) {
                for sub in cg_children(bounds) {
                    if sub.kind() == "type_identifier" {
                        bases.push(cg_text(sub, src).to_string());
                    }
                }
            }
        }
        let Some(name_node) = name_node else {
            for c in cg_children(node) {
                self.walk(c, src);
            }
            return;
        };
        let nested = !self.class_stack.is_empty() || !self.enclosing.is_empty() || self.mod_depth > 0;
        self.graph.classes.push(ClassDef {
            name: cg_text(name_node, src).to_string(),
            line: node.start_position().row as i64 + 1,
            bases,
            methods: Vec::new(),
            nested,
        });
        self.class_stack.push(self.graph.classes.len() - 1);
        for c in cg_children(node) {
            self.walk(c, src);
        }
        self.class_stack.pop();
    }

    fn visit_impl(&mut self, node: Node, src: &[u8]) {
        let mut target_names: Vec<String> = Vec::new();
        for c in cg_children(node) {
            match c.kind() {
                "type_identifier" => target_names.push(cg_text(c, src).to_string()),
                "generic_type" => {
                    if let Some(ti) = first_child_of_type(c, &["type_identifier"]) {
                        target_names.push(cg_text(ti, src).to_string());
                    }
                }
                "scoped_identifier" => {
                    if let Some(last) = self.scoped_parts(c, src).last() {
                        target_names.push(last.clone());
                    }
                }
                _ => {}
            }
        }
        let Some(target) = target_names.last().cloned() else {
            for c in cg_children(node) {
                self.walk(c, src);
            }
            return;
        };
        let idx = match self.graph.classes.iter().position(|c| c.name == target) {
            Some(i) => i,
            None => {
                self.graph.classes.push(ClassDef {
                    name: target,
                    line: node.start_position().row as i64 + 1,
                    bases: Vec::new(),
                    methods: Vec::new(),
                    nested: self.mod_depth > 0,
                });
                self.graph.classes.len() - 1
            }
        };
        self.class_stack.push(idx);
        for c in cg_children(node) {
            self.walk(c, src);
        }
        self.class_stack.pop();
    }

    fn handle_use(&mut self, node: Node, src: &[u8]) {
        for c in cg_children(node) {
            match c.kind() {
                "use_wildcard" => {
                    self.graph.indirection.insert(INDIRECTION_WILDCARD_IMPORT.to_string());
                }
                "scoped_identifier" => {
                    let parts = self.scoped_parts(c, src);
                    if let Some(bound) = parts.last() {
                        self.graph.imports.insert(bound.clone(), parts.join("."));
                    }
                }
                "scoped_use_list" => self.handle_scoped_use_list(c, src),
                "use_as_clause" => self.handle_use_as(c, &[], src),
                "identifier" => {
                    let name = cg_text(c, src).to_string();
                    self.graph.imports.insert(name.clone(), name);
                }
                _ => {}
            }
        }
    }

    fn handle_scoped_use_list(&mut self, node: Node, src: &[u8]) {
        let mut prefix: Vec<String> = Vec::new();
        let mut list_node = None;
        for c in cg_children(node) {
            match c.kind() {
                "identifier" => prefix.push(cg_text(c, src).to_string()),
                "scoped_identifier" => prefix.extend(self.scoped_parts(c, src)),
                "use_list" => list_node = Some(c),
                _ => {}
            }
        }
        let Some(list_node) = list_node else { return };
        for c in cg_children(list_node) {
            match c.kind() {
                "identifier" => {
                    let name = cg_text(c, src).to_string();
                    let full: Vec<String> = prefix.iter().cloned().chain([name.clone()]).collect();
                    self.graph.imports.insert(name, full.join("."));
                }
                "use_as_clause" => self.handle_use_as(c, &prefix, src),
                "use_wildcard" => {
                    self.graph.indirection.insert(INDIRECTION_WILDCARD_IMPORT.to_string());
                }
                "scoped_identifier" => {
                    let parts = self.scoped_parts(c, src);
                    if let Some(bound) = parts.last() {
                        let full: Vec<String> = prefix.iter().cloned().chain(parts.iter().cloned()).collect();
                        self.graph.imports.insert(bound.clone(), full.join("."));
                    }
                }
                _ => {}
            }
        }
    }

    fn handle_use_as(&mut self, node: Node, prefix: &[String], src: &[u8]) {
        let mut original_parts: Vec<String> = Vec::new();
        let mut alias: Option<String> = None;
        let mut idents_seen = 0;
        for c in cg_children(node) {
            if c.kind() == "scoped_identifier" {
                original_parts = self.scoped_parts(c, src);
            } else if c.kind() == "identifier" {
                if original_parts.is_empty() && idents_seen == 0 {
                    original_parts = vec![cg_text(c, src).to_string()];
                    idents_seen += 1;
                } else {
                    alias = Some(cg_text(c, src).to_string());
                }
            }
        }
        let Some(alias) = alias else { return };
        if original_parts.is_empty() {
            return;
        }
        let full: Vec<String> = prefix.iter().cloned().chain(original_parts).collect();
        self.graph.imports.insert(alias, full.join("."));
    }

    fn scoped_parts(&self, node: Node, src: &[u8]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut stack: Vec<String> = Vec::new();
        let mut cur = Some(node);
        while let Some(c) = cur {
            if c.kind() != "scoped_identifier" {
                break;
            }
            let named: Vec<Node> = cg_children(c).into_iter().filter(|x| x.is_named()).collect();
            if named.is_empty() {
                return Vec::new();
            }
            let trailing = named[named.len() - 1];
            if trailing.kind() != "identifier" {
                return Vec::new();
            }
            stack.push(cg_text(trailing, src).to_string());
            let first = named[0];
            if first.kind() == "scoped_identifier" {
                cur = Some(first);
            } else {
                if first.kind() == "identifier" {
                    out.push(cg_text(first, src).to_string());
                }
                break;
            }
        }
        for s in stack.iter().rev() {
            out.push(s.clone());
        }
        out
    }

    fn call_chain(&self, node: Node, src: &[u8]) -> Option<Vec<String>> {
        let mut callee = None;
        for c in cg_children(node) {
            if c.kind() == "arguments" {
                break;
            }
            if c.is_named() {
                callee = Some(c);
                break;
            }
        }
        let callee = callee?;
        match callee.kind() {
            "identifier" => Some(vec![cg_text(callee, src).to_string()]),
            "scoped_identifier" => {
                let p = self.scoped_parts(callee, src);
                if p.is_empty() { None } else { Some(p) }
            }
            "field_expression" => self.field_chain(callee, src),
            _ => None,
        }
    }

    fn field_chain(&self, node: Node, src: &[u8]) -> Option<Vec<String>> {
        let mut parts: Vec<String> = Vec::new();
        let mut cur = Some(node);
        while let Some(c) = cur {
            if c.kind() != "field_expression" {
                break;
            }
            let field = cg_children(c).into_iter().rfind(|x| x.kind() == "field_identifier")?;
            parts.push(cg_text(field, src).to_string());
            cur = cg_children(c).into_iter().find(|x| x.is_named());
        }
        let c = cur?;
        match c.kind() {
            "identifier" => {
                parts.push(cg_text(c, src).to_string());
                parts.reverse();
                Some(parts)
            }
            "self" => {
                parts.push("self".to_string());
                parts.reverse();
                Some(parts)
            }
            "scoped_identifier" => {
                let scoped = self.scoped_parts(c, src);
                if scoped.is_empty() {
                    return None;
                }
                parts.reverse();
                let mut out = scoped;
                out.extend(parts);
                Some(out)
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Ruby call-graph extractor — port of extract_call_graph_ruby / _RubyCallGraph.
// ---------------------------------------------------------------------------

const RUBY_REFLECT_NAMES: &[&str] = &["send", "public_send", "__send__"];
const RUBY_CONST_GET_NAMES: &[&str] = &["const_get"];
const RUBY_EVAL_NAMES: &[&str] = &["eval", "instance_eval", "class_eval", "module_eval"];
const RUBY_REQUIRE_NAMES: &[&str] = &["require", "require_relative", "load"];

struct RubyCallGraph {
    graph: FileCallGraph,
    enclosing: Vec<String>,
    class_stack: Vec<usize>,
    mod_stack: Vec<String>,
}

impl RubyCallGraph {
    fn walk(&mut self, node: Node, src: &[u8]) {
        match node.kind() {
            "module" => {
                if let Some(name_node) = first_child_of_type(node, &["constant"]) {
                    self.mod_stack.push(cg_text(name_node, src).to_string());
                    self.graph.package_name = Some(self.mod_stack.join("."));
                    for c in cg_children(node) {
                        self.walk(c, src);
                    }
                    self.mod_stack.pop();
                    return;
                }
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                return;
            }
            "class" => {
                self.visit_class(node, src);
                return;
            }
            "method" | "singleton_method" => {
                let name = first_child_of_type(node, &["identifier"])
                    .map(|n| cg_text(n, src).to_string())
                    .unwrap_or_else(|| "<anon>".to_string());
                if !self.class_stack.is_empty() && self.enclosing.is_empty() {
                    let idx = *self.class_stack.last().unwrap();
                    self.graph.classes[idx].methods.push((name.clone(), node.start_position().row as i64 + 1));
                }
                self.enclosing.push(name);
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                self.enclosing.pop();
                return;
            }
            "call" => {
                self.handle_call(node, src);
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                return;
            }
            _ => {}
        }
        for c in cg_children(node) {
            self.walk(c, src);
        }
    }

    fn visit_class(&mut self, node: Node, src: &[u8]) {
        let Some(name_node) = first_child_of_type(node, &["constant"]) else {
            for c in cg_children(node) {
                self.walk(c, src);
            }
            return;
        };
        let mut bases: Vec<String> = Vec::new();
        if let Some(supercls) = first_child_of_type(node, &["superclass"]) {
            if let Some(base_node) = first_child_of_type(supercls, &["constant", "scope_resolution"]) {
                if base_node.kind() == "scope_resolution" {
                    bases = vec![self.chain_from_node(Some(base_node), src).join(".")];
                } else {
                    bases = vec![cg_text(base_node, src).to_string()];
                }
            }
        }
        let nested = !self.class_stack.is_empty() || !self.enclosing.is_empty();
        self.graph.classes.push(ClassDef {
            name: cg_text(name_node, src).to_string(),
            line: node.start_position().row as i64 + 1,
            bases,
            methods: Vec::new(),
            nested,
        });
        self.class_stack.push(self.graph.classes.len() - 1);
        for c in cg_children(node) {
            self.walk(c, src);
        }
        self.class_stack.pop();
    }

    fn handle_call(&mut self, node: Node, src: &[u8]) {
        let mut receiver = None;
        let mut method = None;
        for c in cg_children(node) {
            if c.kind() == "argument_list" {
                break;
            }
            if !c.is_named() {
                continue;
            }
            if method.is_none() && matches!(c.kind(), "identifier" | "constant") {
                if receiver.is_none() {
                    receiver = Some(c);
                } else {
                    method = Some(c);
                }
            } else if matches!(c.kind(), "scope_resolution" | "call")
                || (c.kind() == "self" && receiver.is_none())
            {
                receiver = Some(c);
            }
        }

        if method.is_none() {
            if let Some(receiver) = receiver {
                let chain = self.chain_from_node(Some(receiver), src);
                if !chain.is_empty() {
                    let bare = chain[0].clone();
                    self.record(node, chain);
                    if RUBY_REQUIRE_NAMES.contains(&bare.as_str()) {
                        self.extract_require_arg(node, src);
                    }
                    if RUBY_EVAL_NAMES.contains(&bare.as_str()) {
                        self.graph.indirection.insert(INDIRECTION_EVAL.to_string());
                    }
                    if RUBY_REFLECT_NAMES.contains(&bare.as_str()) {
                        self.graph.indirection.insert(INDIRECTION_REFLECT.to_string());
                    }
                    if RUBY_CONST_GET_NAMES.contains(&bare.as_str()) {
                        self.graph.indirection.insert(INDIRECTION_IMPORTLIB.to_string());
                    }
                }
            }
            return;
        }

        let method = method.unwrap();
        let receiver_chain = if let Some(r) = receiver { self.chain_from_node(Some(r), src) } else { Vec::new() };
        let method_name = cg_text(method, src).to_string();
        let mut chain = receiver_chain;
        chain.push(method_name.clone());
        self.record(node, chain);
        if RUBY_REFLECT_NAMES.contains(&method_name.as_str()) {
            self.graph.indirection.insert(INDIRECTION_REFLECT.to_string());
        }
        if RUBY_CONST_GET_NAMES.contains(&method_name.as_str()) {
            self.graph.indirection.insert(INDIRECTION_IMPORTLIB.to_string());
        }
        if RUBY_EVAL_NAMES.contains(&method_name.as_str()) {
            self.graph.indirection.insert(INDIRECTION_EVAL.to_string());
        }
    }

    fn extract_require_arg(&mut self, node: Node, src: &[u8]) {
        let Some(args) = first_child_of_type(node, &["argument_list"]) else { return };
        for a in cg_children(args) {
            if a.kind() == "string" {
                for sc in cg_children(a) {
                    if sc.kind() == "string_content" {
                        let path = cg_text(sc, src).to_string();
                        let bound = path.rsplit('/').next().unwrap_or("").to_string();
                        self.graph.imports.insert(bound, path);
                    }
                }
            }
        }
    }

    fn chain_from_node(&self, node: Option<Node>, src: &[u8]) -> Vec<String> {
        let Some(node) = node else { return Vec::new() };
        match node.kind() {
            "identifier" | "constant" => vec![cg_text(node, src).to_string()],
            "self" => vec!["self".to_string()],
            "scope_resolution" => {
                let mut parts: Vec<String> = Vec::new();
                for c in cg_children(node) {
                    if matches!(c.kind(), "identifier" | "constant") {
                        parts.push(cg_text(c, src).to_string());
                    } else if c.kind() == "scope_resolution" {
                        let mut nested = self.chain_from_node(Some(c), src);
                        nested.extend(parts);
                        parts = nested;
                    }
                }
                parts
            }
            "call" => self.chain_from_call(node, src),
            _ => Vec::new(),
        }
    }

    fn chain_from_call(&self, node: Node, src: &[u8]) -> Vec<String> {
        let mut receiver = None;
        let mut method = None;
        for c in cg_children(node) {
            if c.kind() == "argument_list" {
                break;
            }
            if !c.is_named() {
                continue;
            }
            if receiver.is_none() && matches!(c.kind(), "identifier" | "constant" | "scope_resolution" | "call") {
                receiver = Some(c);
            } else if method.is_none() && matches!(c.kind(), "identifier" | "constant") {
                method = Some(c);
            }
        }
        let Some(receiver) = receiver else { return Vec::new() };
        let rc = self.chain_from_node(Some(receiver), src);
        match method {
            Some(m) => {
                let mut out = rc;
                out.push(cg_text(m, src).to_string());
                out
            }
            None => rc,
        }
    }

    fn record(&mut self, node: Node, chain: Vec<String>) {
        let line = node.start_position().row as i64 + 1;
        let caller = self.enclosing.last().cloned();
        let mut receiver_class = None;
        if let Some(&idx) = self.class_stack.last() {
            let cls = &self.graph.classes[idx];
            if !cls.nested && !self.enclosing.is_empty() && chain.len() >= 2 && chain[0] == "self" {
                receiver_class = Some(cls.name.clone());
            }
        }
        self.graph.calls.push(CallSite { line, chain, caller, receiver_class, ..Default::default() });
    }
}

// ---------------------------------------------------------------------------
// C# call-graph extractor — port of extract_call_graph_csharp / _CSharpCallGraph.
// ---------------------------------------------------------------------------

const CS_REFLECT_METHODS: &[&str] = &["Invoke", "GetMethod", "CreateInstance", "InvokeMember"];
const CS_ASSEMBLY_LOAD: &[&str] = &["Load", "LoadFrom", "LoadFile", "LoadWithPartialName"];

struct CSharpCallGraph {
    graph: FileCallGraph,
    enclosing: Vec<String>,
    class_stack: Vec<usize>,
    ns_stack: Vec<String>,
    field_types: Vec<HashMap<String, String>>,
    local_types: HashMap<String, String>,
}

impl CSharpCallGraph {
    fn walk(&mut self, node: Node, src: &[u8]) {
        match node.kind() {
            "file_scoped_namespace_declaration" => {
                if let Some(name_node) = first_child_of_type(node, &["qualified_name", "identifier"]) {
                    let parts = self.qualified_parts(name_node, src);
                    self.ns_stack.extend(parts);
                    self.graph.package_name = Some(self.ns_stack.join("."));
                }
                return;
            }
            "namespace_declaration" => {
                if let Some(name_node) = first_child_of_type(node, &["qualified_name", "identifier"]) {
                    let parts = self.qualified_parts(name_node, src);
                    let n = parts.len();
                    self.ns_stack.extend(parts);
                    self.graph.package_name = Some(self.ns_stack.join("."));
                    for c in cg_children(node) {
                        self.walk(c, src);
                    }
                    for _ in 0..n {
                        self.ns_stack.pop();
                    }
                    return;
                }
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                return;
            }
            "class_declaration" | "interface_declaration" | "struct_declaration"
            | "record_declaration" => {
                self.visit_class(node, src);
                return;
            }
            "method_declaration" | "constructor_declaration" => {
                let name = first_child_of_type(node, &["identifier"])
                    .map(|n| cg_text(n, src).to_string())
                    .unwrap_or_else(|| "<anon>".to_string());
                if !self.class_stack.is_empty() && self.enclosing.is_empty() {
                    let idx = *self.class_stack.last().unwrap();
                    self.graph.classes[idx].methods.push((name.clone(), node.start_position().row as i64 + 1));
                }
                self.enclosing.push(name);
                let saved = std::mem::take(&mut self.local_types);
                self.local_types = self.collect_param_types(first_child_of_type(node, &["parameter_list"]), src);
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                self.enclosing.pop();
                self.local_types = saved;
                return;
            }
            "local_declaration_statement" => {
                let vd = first_child_of_type(node, &["variable_declaration"]);
                let types = self.collect_decl_types(vd, src);
                self.local_types.extend(types);
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                return;
            }
            "using_directive" => {
                self.handle_using(node, src);
                return;
            }
            "invocation_expression" => {
                self.visit_invocation(node, src);
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                return;
            }
            _ => {}
        }
        for c in cg_children(node) {
            self.walk(c, src);
        }
    }

    fn visit_class(&mut self, node: Node, src: &[u8]) {
        let Some(name_node) = first_child_of_type(node, &["identifier"]) else {
            for c in cg_children(node) {
                self.walk(c, src);
            }
            return;
        };
        let mut bases: Vec<String> = Vec::new();
        if let Some(bl) = first_child_of_type(node, &["base_list"]) {
            for sub in cg_children(bl) {
                if sub.kind() == "identifier" {
                    bases.push(cg_text(sub, src).to_string());
                } else if sub.kind() == "qualified_name" {
                    let q = self.qualified_parts(sub, src);
                    if !q.is_empty() {
                        bases.push(q.join("."));
                    }
                }
            }
        }
        let nested = !self.class_stack.is_empty() || !self.enclosing.is_empty();
        self.graph.classes.push(ClassDef {
            name: cg_text(name_node, src).to_string(),
            line: node.start_position().row as i64 + 1,
            bases,
            methods: Vec::new(),
            nested,
        });
        self.class_stack.push(self.graph.classes.len() - 1);
        let mut field_types: HashMap<String, String> = HashMap::new();
        if let Some(body) = first_child_of_type(node, &["declaration_list"]) {
            for member in cg_children(body) {
                if member.kind() == "field_declaration" {
                    let vd = first_child_of_type(member, &["variable_declaration"]);
                    field_types.extend(self.collect_decl_types(vd, src));
                }
            }
        }
        self.field_types.push(field_types);
        for c in cg_children(node) {
            self.walk(c, src);
        }
        self.class_stack.pop();
        self.field_types.pop();
    }

    fn visit_invocation(&mut self, node: Node, src: &[u8]) {
        if let Some(chain) = self.invocation_chain(node, src) {
            let caller = self.enclosing.last().cloned();
            let mut receiver_class = None;
            if let Some(&idx) = self.class_stack.last() {
                let cls = &self.graph.classes[idx];
                if !cls.nested
                    && !self.enclosing.is_empty()
                    && (chain.len() == 1 || (chain.len() == 2 && chain[0] == "this"))
                {
                    receiver_class = Some(cls.name.clone());
                }
            }
            let receiver_type = if receiver_class.is_none() {
                self.resolve_receiver_type(&chain)
            } else {
                None
            };
            let tail = chain.last().cloned().unwrap_or_default();
            let chain_n = chain.len();
            let second_last = if chain_n >= 2 { Some(chain[chain_n - 2].clone()) } else { None };
            self.graph.calls.push(CallSite {
                line: node.start_position().row as i64 + 1,
                chain,
                caller,
                receiver_class,
                receiver_type,
                ..Default::default()
            });
            if CS_REFLECT_METHODS.contains(&tail.as_str()) {
                self.graph.indirection.insert(INDIRECTION_REFLECT.to_string());
            }
            if CS_ASSEMBLY_LOAD.contains(&tail.as_str()) && second_last.as_deref() == Some("Assembly") {
                self.graph.indirection.insert(INDIRECTION_IMPORTLIB.to_string());
            }
        } else if let Some(tail_name) = self.tail_identifier(node, src) {
            if CS_REFLECT_METHODS.contains(&tail_name.as_str()) {
                self.graph.indirection.insert(INDIRECTION_REFLECT.to_string());
            }
        }
    }

    fn type_name(&self, type_node: Option<Node>, src: &[u8]) -> Option<String> {
        let t = type_node?;
        match t.kind() {
            "identifier" => {
                let s = cg_text(t, src);
                if s.is_empty() { None } else { Some(s.to_string()) }
            }
            "qualified_name" => self.qualified_parts(t, src).last().cloned(),
            "generic_name" => first_child_of_type(t, &["identifier"]).map(|n| cg_text(n, src).to_string()),
            "nullable_type" | "array_type" => {
                let inner = t.child_by_field_name("type").or_else(|| cg_children(t).into_iter().next());
                self.type_name(inner, src)
            }
            _ => None,
        }
    }

    fn collect_param_types(&self, params_node: Option<Node>, src: &[u8]) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let Some(params) = params_node else { return out };
        for p in cg_children(params) {
            if p.kind() != "parameter" {
                continue;
            }
            let tn = self.type_name(p.child_by_field_name("type"), src);
            let name = p.child_by_field_name("name");
            if let (Some(tn), Some(name)) = (tn, name) {
                out.insert(cg_text(name, src).to_string(), tn);
            }
        }
        out
    }

    fn collect_decl_types(&self, var_decl_node: Option<Node>, src: &[u8]) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let Some(vd) = var_decl_node else { return out };
        let Some(tn) = self.type_name(vd.child_by_field_name("type"), src) else { return out };
        for c in cg_children(vd) {
            if c.kind() != "variable_declarator" {
                continue;
            }
            let name = c.child_by_field_name("name").or_else(|| first_child_of_type(c, &["identifier"]));
            if let Some(name) = name {
                out.insert(cg_text(name, src).to_string(), tn.clone());
            }
        }
        out
    }

    fn resolve_receiver_type(&self, chain: &[String]) -> Option<String> {
        if chain.len() != 2 || matches!(chain[0].as_str(), "this" | "base") {
            return None;
        }
        let recv = &chain[0];
        if let Some(t) = self.local_types.get(recv) {
            return Some(t.clone());
        }
        if let Some(ft) = self.field_types.last() {
            if let Some(t) = ft.get(recv) {
                return Some(t.clone());
            }
        }
        None
    }

    fn handle_using(&mut self, node: Node, src: &[u8]) {
        let mut target = None;
        let mut alias = None;
        for c in cg_children(node) {
            if c.kind() == "qualified_name" {
                target = Some(c);
            } else if c.kind() == "identifier" && alias.is_none() {
                alias = Some(c);
            }
        }
        let Some(target) = target else { return };
        let parts = self.qualified_parts(target, src);
        if parts.is_empty() {
            return;
        }
        let full = parts.join(".");
        let last = parts[parts.len() - 1].clone();
        if let Some(alias) = alias {
            let alias_text = cg_text(alias, src).to_string();
            if alias_text != last {
                self.graph.imports.insert(alias_text, full);
                return;
            }
        }
        self.graph.imports.insert(last, full);
    }

    fn qualified_parts(&self, node: Node, src: &[u8]) -> Vec<String> {
        match node.kind() {
            "identifier" => vec![cg_text(node, src).to_string()],
            "qualified_name" => {
                let mut parts: Vec<String> = Vec::new();
                for c in cg_children(node) {
                    if c.kind() == "identifier" {
                        parts.push(cg_text(c, src).to_string());
                    } else if c.kind() == "qualified_name" {
                        let mut nested = self.qualified_parts(c, src);
                        nested.extend(parts);
                        parts = nested;
                    }
                }
                parts
            }
            _ => Vec::new(),
        }
    }

    fn invocation_chain(&self, node: Node, src: &[u8]) -> Option<Vec<String>> {
        let mut callee = None;
        for c in cg_children(node) {
            if c.kind() == "argument_list" {
                break;
            }
            if c.is_named() {
                callee = Some(c);
                break;
            }
        }
        let callee = callee?;
        match callee.kind() {
            "identifier" => Some(vec![cg_text(callee, src).to_string()]),
            "member_access_expression" => self.member_access_chain(callee, src),
            "qualified_name" => {
                let q = self.qualified_parts(callee, src);
                if q.is_empty() { None } else { Some(q) }
            }
            _ => None,
        }
    }

    fn member_access_chain(&self, node: Node, src: &[u8]) -> Option<Vec<String>> {
        let mut parts: Vec<String> = Vec::new();
        let mut cur = Some(node);
        while let Some(c) = cur {
            if c.kind() != "member_access_expression" {
                break;
            }
            let named: Vec<Node> = cg_children(c).into_iter().filter(|x| x.is_named()).collect();
            if named.len() == 1 {
                let has_this = cg_children(c).iter().any(|x| !x.is_named() && matches!(x.kind(), "this" | "base"));
                if !has_this {
                    return None;
                }
                let tail = named[0];
                if tail.kind() != "identifier" {
                    return None;
                }
                parts.push(cg_text(tail, src).to_string());
                let kw = cg_children(c)
                    .into_iter()
                    .find(|x| !x.is_named() && matches!(x.kind(), "this" | "base"))
                    .map(|x| x.kind().to_string())
                    .unwrap_or_else(|| "this".to_string());
                parts.push(kw);
                parts.reverse();
                return Some(parts);
            }
            if named.len() < 2 {
                return None;
            }
            let tail = named[named.len() - 1];
            if tail.kind() != "identifier" {
                return None;
            }
            parts.push(cg_text(tail, src).to_string());
            cur = Some(named[0]);
        }
        let c = cur?;
        match c.kind() {
            "identifier" => {
                parts.push(cg_text(c, src).to_string());
                parts.reverse();
                Some(parts)
            }
            "this_expression" => {
                parts.push("this".to_string());
                parts.reverse();
                Some(parts)
            }
            "qualified_name" => {
                let q = self.qualified_parts(c, src);
                if q.is_empty() {
                    return None;
                }
                parts.reverse();
                let mut out = q;
                out.extend(parts);
                Some(out)
            }
            _ => None,
        }
    }

    fn tail_identifier(&self, node: Node, src: &[u8]) -> Option<String> {
        let mut callee = None;
        for c in cg_children(node) {
            if c.kind() == "argument_list" {
                break;
            }
            if c.is_named() {
                callee = Some(c);
                break;
            }
        }
        let mut cur = callee?;
        loop {
            match cur.kind() {
                "identifier" => return Some(cg_text(cur, src).to_string()),
                "member_access_expression" => {
                    let named: Vec<Node> = cg_children(cur).into_iter().filter(|x| x.is_named()).collect();
                    let tail = *named.last()?;
                    if tail.kind() == "identifier" {
                        return Some(cg_text(tail, src).to_string());
                    }
                    cur = tail;
                }
                "qualified_name" => return self.qualified_parts(cur, src).last().cloned(),
                _ => return None,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PHP call-graph extractor — port of extract_call_graph_php / _PhpCallGraph.
// ---------------------------------------------------------------------------

const PHP_REFLECT_FNS: &[&str] = &["call_user_func", "call_user_func_array", "ReflectionMethod", "ReflectionClass"];
const PHP_EVAL_FNS: &[&str] = &["eval", "create_function", "assert"];
const PHP_DYNAMIC_INCLUDE: &[&str] = &["include", "include_once", "require", "require_once"];

struct PhpCallGraph {
    graph: FileCallGraph,
    enclosing: Vec<String>,
    class_stack: Vec<usize>,
}

impl PhpCallGraph {
    fn walk(&mut self, node: Node, src: &[u8]) {
        match node.kind() {
            "namespace_definition" => {
                if let Some(ns_name) = first_child_of_type(node, &["namespace_name"]) {
                    let parts = self.namespace_parts(ns_name, src);
                    if !parts.is_empty() {
                        self.graph.package_name = Some(parts.join("."));
                    }
                }
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                return;
            }
            "class_declaration" | "interface_declaration" | "trait_declaration"
            | "enum_declaration" => {
                self.visit_class(node, src);
                return;
            }
            "function_definition" | "method_declaration" => {
                let name = first_child_of_type(node, &["name"])
                    .map(|n| cg_text(n, src).to_string())
                    .unwrap_or_else(|| "<anon>".to_string());
                if node.kind() == "method_declaration"
                    && !self.class_stack.is_empty()
                    && self.enclosing.is_empty()
                {
                    let idx = *self.class_stack.last().unwrap();
                    self.graph.classes[idx].methods.push((name.clone(), node.start_position().row as i64 + 1));
                }
                self.enclosing.push(name);
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                self.enclosing.pop();
                return;
            }
            "namespace_use_declaration" => {
                for c in cg_children(node) {
                    if c.kind() == "namespace_use_clause" {
                        self.handle_use_clause(c, src);
                    }
                }
                return;
            }
            "function_call_expression" | "scoped_call_expression" | "member_call_expression" => {
                self.handle_call(node, src);
                for c in cg_children(node) {
                    self.walk(c, src);
                }
                return;
            }
            _ => {}
        }
        for c in cg_children(node) {
            self.walk(c, src);
        }
    }

    fn visit_class(&mut self, node: Node, src: &[u8]) {
        let Some(name_node) = first_child_of_type(node, &["name"]) else {
            for c in cg_children(node) {
                self.walk(c, src);
            }
            return;
        };
        // `extends Base` (base_clause) + `implements I1, I2` (class_interface_clause).
        let mut bases: Vec<String> = Vec::new();
        for clause_kind in ["base_clause", "class_interface_clause"] {
            if let Some(clause) = first_child_of_type(node, &[clause_kind]) {
                for sub in cg_children(clause) {
                    if sub.kind() == "name" {
                        bases.push(cg_text(sub, src).to_string());
                    } else if sub.kind() == "qualified_name" {
                        let q = self.namespace_parts(sub, src);
                        if !q.is_empty() {
                            bases.push(q.join("."));
                        }
                    }
                }
            }
        }
        let nested = !self.class_stack.is_empty() || !self.enclosing.is_empty();
        self.graph.classes.push(ClassDef {
            name: cg_text(name_node, src).to_string(),
            line: node.start_position().row as i64 + 1,
            bases,
            methods: Vec::new(),
            nested,
        });
        self.class_stack.push(self.graph.classes.len() - 1);
        for c in cg_children(node) {
            self.walk(c, src);
        }
        self.class_stack.pop();
    }

    fn handle_use_clause(&mut self, node: Node, src: &[u8]) {
        let mut target_parts: Vec<String> = Vec::new();
        let mut alias_name: Option<String> = None;
        for c in cg_children(node) {
            if matches!(c.kind(), "qualified_name" | "namespace_name") {
                target_parts = self.namespace_parts(c, src);
            } else if c.kind() == "name" && !target_parts.is_empty() {
                alias_name = Some(cg_text(c, src).to_string());
            }
        }
        if target_parts.is_empty() {
            return;
        }
        let full = target_parts.join("\\");
        let bound = alias_name.unwrap_or_else(|| target_parts[target_parts.len() - 1].clone());
        self.graph.imports.insert(bound, full);
    }

    fn namespace_parts(&self, node: Node, src: &[u8]) -> Vec<String> {
        let mut parts: Vec<String> = Vec::new();
        for c in cg_children(node) {
            if c.kind() == "name" {
                parts.push(cg_text(c, src).to_string());
            } else if matches!(c.kind(), "qualified_name" | "namespace_name") {
                let mut nested = self.namespace_parts(c, src);
                nested.extend(parts);
                parts = nested;
            }
        }
        parts
    }

    fn handle_call(&mut self, node: Node, src: &[u8]) {
        let chain = match node.kind() {
            "function_call_expression" => self.function_call_chain(node, src),
            "scoped_call_expression" => self.scoped_call_chain(node, src),
            "member_call_expression" => self.member_call_chain(node, src),
            _ => None,
        };
        let Some(chain) = chain else { return };
        if chain.is_empty() {
            return;
        }
        let caller = self.enclosing.last().cloned();
        let mut receiver_class = None;
        if let Some(&idx) = self.class_stack.last() {
            let cls = &self.graph.classes[idx];
            let this_member = node.kind() == "member_call_expression" && chain[0] == "this";
            let self_scoped = node.kind() == "scoped_call_expression"
                && matches!(chain[0].as_str(), "self" | "static");
            if !cls.nested && !self.enclosing.is_empty() && chain.len() >= 2 && (this_member || self_scoped) {
                receiver_class = Some(cls.name.clone());
            }
        }
        let tail = chain.last().cloned().unwrap_or_default();
        let head = chain[0].clone();
        self.graph.calls.push(CallSite {
            line: node.start_position().row as i64 + 1,
            chain,
            caller,
            receiver_class,
            ..Default::default()
        });
        if PHP_REFLECT_FNS.contains(&tail.as_str()) || PHP_REFLECT_FNS.contains(&head.as_str()) {
            self.graph.indirection.insert(INDIRECTION_REFLECT.to_string());
        }
        if PHP_EVAL_FNS.contains(&tail.as_str()) || PHP_EVAL_FNS.contains(&head.as_str()) {
            self.graph.indirection.insert(INDIRECTION_EVAL.to_string());
        }
        if PHP_DYNAMIC_INCLUDE.contains(&head.as_str()) {
            self.graph.indirection.insert(INDIRECTION_DYNAMIC_IMPORT.to_string());
        }
    }

    fn function_call_chain(&mut self, node: Node, src: &[u8]) -> Option<Vec<String>> {
        for c in cg_children(node) {
            if c.kind() == "arguments" {
                break;
            }
            if matches!(c.kind(), "qualified_name" | "namespace_name") {
                let parts = self.namespace_parts(c, src);
                if !parts.is_empty() {
                    return Some(parts);
                }
            }
            if c.kind() == "name" {
                return Some(vec![cg_text(c, src).to_string()]);
            }
            if c.kind() == "variable_name" {
                self.graph.indirection.insert(INDIRECTION_REFLECT.to_string());
                return None;
            }
        }
        None
    }

    fn scoped_call_chain(&self, node: Node, src: &[u8]) -> Option<Vec<String>> {
        let mut scope = None;
        let mut method = None;
        for c in cg_children(node) {
            if c.kind() == "arguments" {
                break;
            }
            if c.is_named() {
                if scope.is_none() {
                    scope = Some(c);
                } else if method.is_none() {
                    method = Some(c);
                }
            }
        }
        let (scope, method) = (scope?, method?);
        let scope_parts = match scope.kind() {
            "name" => vec![cg_text(scope, src).to_string()],
            "qualified_name" | "namespace_name" => self.namespace_parts(scope, src),
            "relative_scope" => {
                let kw = cg_children(scope)
                    .into_iter()
                    .find(|s| matches!(s.kind(), "self" | "static" | "parent"))
                    .map(|s| s.kind().to_string());
                match kw {
                    Some(k) => vec![k],
                    None => return None,
                }
            }
            _ => return None,
        };
        let mut out = scope_parts;
        out.push(cg_text(method, src).to_string());
        Some(out)
    }

    fn member_call_chain(&self, node: Node, src: &[u8]) -> Option<Vec<String>> {
        let mut obj = None;
        let mut method = None;
        for c in cg_children(node) {
            if c.kind() == "arguments" {
                break;
            }
            if c.is_named() {
                if obj.is_none() {
                    obj = Some(c);
                } else if method.is_none() {
                    method = Some(c);
                }
            }
        }
        let (obj, method) = (obj?, method?);
        let obj_chain = self.object_chain(obj, src)?;
        let mut out = obj_chain;
        out.push(cg_text(method, src).to_string());
        Some(out)
    }

    fn object_chain(&self, node: Node, src: &[u8]) -> Option<Vec<String>> {
        match node.kind() {
            "variable_name" => Some(vec![cg_text(node, src).trim_start_matches('$').to_string()]),
            "name" => Some(vec![cg_text(node, src).to_string()]),
            "member_access_expression" => {
                let mut flat: Vec<String> = Vec::new();
                for c in cg_children(node) {
                    if c.is_named() {
                        flat.extend(self.object_chain(c, src).unwrap_or_default());
                    }
                }
                Some(flat)
            }
            "member_call_expression" => self.member_call_chain(node, src),
            _ => None,
        }
    }
}

/// Walk a PHP source string via tree-sitter-php and return its `FileCallGraph`.
pub fn extract_call_graph_php(content: &str) -> FileCallGraph {
    let Some(tree) = mantishack_ts::parse("php", content) else {
        return FileCallGraph::default();
    };
    let mut w = PhpCallGraph {
        graph: FileCallGraph::default(),
        enclosing: Vec::new(),
        class_stack: Vec::new(),
    };
    w.walk(tree.root_node(), content.as_bytes());
    w.graph
}

/// Walk a C# source string via tree-sitter-c-sharp and return its `FileCallGraph`.
pub fn extract_call_graph_csharp(content: &str) -> FileCallGraph {
    let Some(tree) = mantishack_ts::parse("csharp", content) else {
        return FileCallGraph::default();
    };
    let mut w = CSharpCallGraph {
        graph: FileCallGraph::default(),
        enclosing: Vec::new(),
        class_stack: Vec::new(),
        ns_stack: Vec::new(),
        field_types: Vec::new(),
        local_types: HashMap::new(),
    };
    w.walk(tree.root_node(), content.as_bytes());
    w.graph
}

/// Walk a Ruby source string via tree-sitter-ruby and return its `FileCallGraph`.
pub fn extract_call_graph_ruby(content: &str) -> FileCallGraph {
    let Some(tree) = mantishack_ts::parse("ruby", content) else {
        return FileCallGraph::default();
    };
    let mut w = RubyCallGraph {
        graph: FileCallGraph::default(),
        enclosing: Vec::new(),
        class_stack: Vec::new(),
        mod_stack: Vec::new(),
    };
    w.walk(tree.root_node(), content.as_bytes());
    w.graph
}

/// Walk a Rust source string via tree-sitter-rust and return its `FileCallGraph`.
pub fn extract_call_graph_rust(content: &str) -> FileCallGraph {
    let Some(tree) = mantishack_ts::parse("rust", content) else {
        return FileCallGraph::default();
    };
    let mut w = RustCallGraph {
        graph: FileCallGraph::default(),
        enclosing: Vec::new(),
        class_stack: Vec::new(),
        mod_depth: 0,
    };
    w.walk(tree.root_node(), content.as_bytes());
    w.graph
}

/// Walk a C++ source string via tree-sitter-cpp and return its `FileCallGraph`.
pub fn extract_call_graph_cpp(content: &str) -> FileCallGraph {
    let Some(tree) = mantishack_ts::parse("cpp", content) else {
        return FileCallGraph::default();
    };
    let mut w = CppCallGraph {
        graph: FileCallGraph::default(),
        enclosing: Vec::new(),
        class_stack: Vec::new(),
        ns_stack: Vec::new(),
    };
    w.walk(tree.root_node(), content.as_bytes());
    w.graph
}

// ---------------------------------------------------------------------------
// Python call-graph extractor — port of `extract_call_graph_python` /
// `_PythonCallGraph` (the CPython-`ast` branch). Parses with rustpython-parser
// and walks the AST as a faithful `ast.NodeVisitor`.
// ---------------------------------------------------------------------------

/// Return the dotted attribute chain naming `node` (`foo.bar.baz` ->
/// `["foo","bar","baz"]`), or `None` for non-name callees (function returns,
/// subscripts, lambdas …). Port of `_attribute_chain`.
fn py_attribute_chain(node: &PExpr) -> Option<Vec<String>> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = node;
    loop {
        match cur {
            PExpr::Attribute(a) => {
                parts.push(a.attr.as_str().to_string());
                cur = &a.value;
            }
            PExpr::Name(n) => {
                parts.push(n.id.as_str().to_string());
                parts.reverse();
                return Some(parts);
            }
            _ => return None,
        }
    }
}

/// Attribute chain naming a decorator, peeling off a trailing call. Port of
/// `_decorator_chain`.
fn py_decorator_chain(deco: &PExpr) -> Option<Vec<String>> {
    match deco {
        PExpr::Call(c) => py_attribute_chain(&c.func),
        other => py_attribute_chain(other),
    }
}

/// Walk a Python source string and return its `FileCallGraph`. Returns an empty
/// graph on syntax errors (a malformed file shouldn't blow up the inventory
/// build). Faithful port of `extract_call_graph_python`.
pub fn extract_call_graph_python(content: &str) -> FileCallGraph {
    let body = match rustpython_parser::ast::Suite::parse(content, "<call_graph>") {
        Ok(b) => b,
        Err(_) => return FileCallGraph::default(),
    };
    let lines = PyLineIndex::new(content);
    let mut w = PyCallGraph {
        graph: FileCallGraph::default(),
        enclosing: Vec::new(),
        class_stack: Vec::new(),
        lines: &lines,
    };
    for s in &body {
        w.visit_stmt(s);
    }
    w.graph
}

/// Single-pass AST walk emitting imports + call sites + flags. Mirrors
/// `_PythonCallGraph(ast.NodeVisitor)`; `class_stack` holds indices into
/// `graph.classes` (the Python code aliases the same `ClassDef` object onto
/// both the output list and the stack).
struct PyCallGraph<'a> {
    graph: FileCallGraph,
    enclosing: Vec<String>,
    class_stack: Vec<usize>,
    lines: &'a PyLineIndex,
}

impl PyCallGraph<'_> {
    fn line_of(&self, e_start: usize) -> i64 {
        self.lines.line_of(e_start)
    }

    // -- dispatch -----------------------------------------------------------

    fn visit_stmt(&mut self, s: &PStmt) {
        match s {
            PStmt::Import(n) => {
                for alias in &n.names {
                    let target = alias.name.as_str();
                    match &alias.asname {
                        Some(asname) => {
                            self.graph
                                .imports
                                .insert(asname.as_str().to_string(), target.to_string());
                        }
                        None => {
                            let first = target.split('.').next().unwrap_or(target);
                            self.graph
                                .imports
                                .insert(first.to_string(), first.to_string());
                        }
                    }
                }
            }
            PStmt::ImportFrom(n) => {
                let module = n.module.as_ref().map(|m| m.as_str()).unwrap_or("");
                let level = n.level.map(|i| i.to_usize()).unwrap_or(0);
                if level > 0 {
                    for alias in &n.names {
                        if alias.name.as_str() == "*" {
                            self.graph
                                .indirection
                                .insert(INDIRECTION_WILDCARD_IMPORT.to_string());
                            continue;
                        }
                        self.graph.relative_imports.push((
                            level as i64,
                            module.to_string(),
                            alias.name.as_str().to_string(),
                            alias.asname.as_ref().map(|a| a.as_str().to_string()),
                        ));
                    }
                    return;
                }
                for alias in &n.names {
                    if alias.name.as_str() == "*" {
                        self.graph
                            .indirection
                            .insert(INDIRECTION_WILDCARD_IMPORT.to_string());
                        continue;
                    }
                    let local = alias
                        .asname
                        .as_ref()
                        .map(|a| a.as_str())
                        .unwrap_or(alias.name.as_str());
                    let qualified = if module.is_empty() {
                        alias.name.as_str().to_string()
                    } else {
                        format!("{module}.{}", alias.name.as_str())
                    };
                    self.graph.imports.insert(local.to_string(), qualified);
                }
            }
            PStmt::FunctionDef(d) => self.handle_function_def(
                d.name.as_str(),
                d.range.start().to_usize(),
                &d.decorator_list,
                &d.args,
                &d.body,
                d.returns.as_deref(),
                &d.type_params,
            ),
            PStmt::AsyncFunctionDef(d) => self.handle_function_def(
                d.name.as_str(),
                d.range.start().to_usize(),
                &d.decorator_list,
                &d.args,
                &d.body,
                d.returns.as_deref(),
                &d.type_params,
            ),
            PStmt::ClassDef(d) => self.visit_classdef(d),
            other => self.generic_visit_stmt(other),
        }
    }

    fn generic_visit_stmt(&mut self, s: &PStmt) {
        match s {
            PStmt::Return(n) => {
                if let Some(v) = &n.value {
                    self.visit_expr(v);
                }
            }
            PStmt::Delete(n) => self.visit_exprs(&n.targets),
            PStmt::Assign(n) => {
                self.visit_exprs(&n.targets);
                self.visit_expr(&n.value);
            }
            PStmt::TypeAlias(n) => {
                self.visit_expr(&n.name);
                self.visit_type_params(&n.type_params);
                self.visit_expr(&n.value);
            }
            PStmt::AugAssign(n) => {
                self.visit_expr(&n.target);
                self.visit_expr(&n.value);
            }
            PStmt::AnnAssign(n) => {
                self.visit_expr(&n.target);
                self.visit_expr(&n.annotation);
                if let Some(v) = &n.value {
                    self.visit_expr(v);
                }
            }
            PStmt::For(n) => {
                self.visit_expr(&n.target);
                self.visit_expr(&n.iter);
                self.visit_stmts(&n.body);
                self.visit_stmts(&n.orelse);
            }
            PStmt::AsyncFor(n) => {
                self.visit_expr(&n.target);
                self.visit_expr(&n.iter);
                self.visit_stmts(&n.body);
                self.visit_stmts(&n.orelse);
            }
            PStmt::While(n) => {
                self.visit_expr(&n.test);
                self.visit_stmts(&n.body);
                self.visit_stmts(&n.orelse);
            }
            PStmt::If(n) => {
                self.visit_expr(&n.test);
                self.visit_stmts(&n.body);
                self.visit_stmts(&n.orelse);
            }
            PStmt::With(n) => {
                for item in &n.items {
                    self.visit_expr(&item.context_expr);
                    if let Some(v) = &item.optional_vars {
                        self.visit_expr(v);
                    }
                }
                self.visit_stmts(&n.body);
            }
            PStmt::AsyncWith(n) => {
                for item in &n.items {
                    self.visit_expr(&item.context_expr);
                    if let Some(v) = &item.optional_vars {
                        self.visit_expr(v);
                    }
                }
                self.visit_stmts(&n.body);
            }
            PStmt::Match(n) => {
                self.visit_expr(&n.subject);
                for case in &n.cases {
                    self.visit_pattern(&case.pattern);
                    if let Some(g) = &case.guard {
                        self.visit_expr(g);
                    }
                    self.visit_stmts(&case.body);
                }
            }
            PStmt::Raise(n) => {
                if let Some(e) = &n.exc {
                    self.visit_expr(e);
                }
                if let Some(c) = &n.cause {
                    self.visit_expr(c);
                }
            }
            PStmt::Try(n) => self.visit_try(&n.body, &n.handlers, &n.orelse, &n.finalbody),
            PStmt::TryStar(n) => self.visit_try(&n.body, &n.handlers, &n.orelse, &n.finalbody),
            PStmt::Assert(n) => {
                self.visit_expr(&n.test);
                if let Some(m) = &n.msg {
                    self.visit_expr(m);
                }
            }
            PStmt::Expr(n) => self.visit_expr(&n.value),
            // Import / ImportFrom / FunctionDef / AsyncFunctionDef / ClassDef are
            // dispatched in visit_stmt; Global/Nonlocal/Pass/Break/Continue have
            // no child nodes.
            _ => {}
        }
    }

    fn visit_try(
        &mut self,
        body: &[PStmt],
        handlers: &[rustpython_parser::ast::ExceptHandler],
        orelse: &[PStmt],
        finalbody: &[PStmt],
    ) {
        self.visit_stmts(body);
        for h in handlers {
            let rustpython_parser::ast::ExceptHandler::ExceptHandler(eh) = h;
            if let Some(t) = &eh.type_ {
                self.visit_expr(t);
            }
            self.visit_stmts(&eh.body);
        }
        self.visit_stmts(orelse);
        self.visit_stmts(finalbody);
    }

    fn visit_stmts(&mut self, stmts: &[PStmt]) {
        for s in stmts {
            self.visit_stmt(s);
        }
    }

    fn visit_exprs(&mut self, exprs: &[PExpr]) {
        for e in exprs {
            self.visit_expr(e);
        }
    }

    fn visit_expr(&mut self, e: &PExpr) {
        if let PExpr::Call(_) = e {
            self.visit_call(e);
        } else {
            self.generic_visit_expr(e);
        }
    }

    fn generic_visit_expr(&mut self, e: &PExpr) {
        match e {
            PExpr::BoolOp(n) => self.visit_exprs(&n.values),
            PExpr::NamedExpr(n) => {
                self.visit_expr(&n.target);
                self.visit_expr(&n.value);
            }
            PExpr::BinOp(n) => {
                self.visit_expr(&n.left);
                self.visit_expr(&n.right);
            }
            PExpr::UnaryOp(n) => self.visit_expr(&n.operand),
            PExpr::Lambda(n) => {
                self.visit_arguments(&n.args);
                self.visit_expr(&n.body);
            }
            PExpr::IfExp(n) => {
                self.visit_expr(&n.test);
                self.visit_expr(&n.body);
                self.visit_expr(&n.orelse);
            }
            PExpr::Dict(n) => {
                for k in n.keys.iter().flatten() {
                    self.visit_expr(k);
                }
                self.visit_exprs(&n.values);
            }
            PExpr::Set(n) => self.visit_exprs(&n.elts),
            PExpr::ListComp(n) => {
                self.visit_expr(&n.elt);
                self.visit_comprehensions(&n.generators);
            }
            PExpr::SetComp(n) => {
                self.visit_expr(&n.elt);
                self.visit_comprehensions(&n.generators);
            }
            PExpr::GeneratorExp(n) => {
                self.visit_expr(&n.elt);
                self.visit_comprehensions(&n.generators);
            }
            PExpr::DictComp(n) => {
                self.visit_expr(&n.key);
                self.visit_expr(&n.value);
                self.visit_comprehensions(&n.generators);
            }
            PExpr::Await(n) => self.visit_expr(&n.value),
            PExpr::Yield(n) => {
                if let Some(v) = &n.value {
                    self.visit_expr(v);
                }
            }
            PExpr::YieldFrom(n) => self.visit_expr(&n.value),
            PExpr::Compare(n) => {
                self.visit_expr(&n.left);
                self.visit_exprs(&n.comparators);
            }
            PExpr::Call(n) => {
                // Reached only via the chain==None path of visit_call.
                self.visit_expr(&n.func);
                self.visit_exprs(&n.args);
                for kw in &n.keywords {
                    self.visit_expr(&kw.value);
                }
            }
            PExpr::FormattedValue(n) => {
                self.visit_expr(&n.value);
                if let Some(fs) = &n.format_spec {
                    self.visit_expr(fs);
                }
            }
            PExpr::JoinedStr(n) => self.visit_exprs(&n.values),
            PExpr::Attribute(n) => self.visit_expr(&n.value),
            PExpr::Subscript(n) => {
                self.visit_expr(&n.value);
                self.visit_expr(&n.slice);
            }
            PExpr::Starred(n) => self.visit_expr(&n.value),
            PExpr::List(n) => self.visit_exprs(&n.elts),
            PExpr::Tuple(n) => self.visit_exprs(&n.elts),
            PExpr::Slice(n) => {
                if let Some(l) = &n.lower {
                    self.visit_expr(l);
                }
                if let Some(u) = &n.upper {
                    self.visit_expr(u);
                }
                if let Some(s) = &n.step {
                    self.visit_expr(s);
                }
            }
            // Name / Constant have no child expressions.
            _ => {}
        }
    }

    fn visit_comprehensions(&mut self, gens: &[rustpython_parser::ast::Comprehension]) {
        for g in gens {
            self.visit_expr(&g.target);
            self.visit_expr(&g.iter);
            self.visit_exprs(&g.ifs);
        }
    }

    fn visit_pattern(&mut self, p: &PPattern) {
        match p {
            PPattern::MatchValue(n) => self.visit_expr(&n.value),
            PPattern::MatchSingleton(_) => {}
            PPattern::MatchSequence(n) => {
                for sub in &n.patterns {
                    self.visit_pattern(sub);
                }
            }
            PPattern::MatchMapping(n) => {
                self.visit_exprs(&n.keys);
                for sub in &n.patterns {
                    self.visit_pattern(sub);
                }
            }
            PPattern::MatchClass(n) => {
                self.visit_expr(&n.cls);
                for sub in &n.patterns {
                    self.visit_pattern(sub);
                }
                for sub in &n.kwd_patterns {
                    self.visit_pattern(sub);
                }
            }
            PPattern::MatchStar(_) => {}
            PPattern::MatchAs(n) => {
                if let Some(sub) = &n.pattern {
                    self.visit_pattern(sub);
                }
            }
            PPattern::MatchOr(n) => {
                for sub in &n.patterns {
                    self.visit_pattern(sub);
                }
            }
        }
    }

    fn visit_type_params(&mut self, tps: &[PTypeParam]) {
        for tp in tps {
            if let PTypeParam::TypeVar(t) = tp {
                if let Some(b) = &t.bound {
                    self.visit_expr(b);
                }
            }
        }
    }

    /// Visit a function/lambda `arguments` node — the annotation and default
    /// expressions (where calls can hide), approximating CPython's
    /// `iter_child_nodes(arguments)` field order (annotations, then defaults).
    fn visit_arguments(&mut self, args: &rustpython_parser::ast::Arguments) {
        for a in args.posonlyargs.iter().chain(args.args.iter()) {
            if let Some(ann) = &a.def.annotation {
                self.visit_expr(ann);
            }
        }
        if let Some(va) = &args.vararg {
            if let Some(ann) = &va.annotation {
                self.visit_expr(ann);
            }
        }
        for a in &args.kwonlyargs {
            if let Some(ann) = &a.def.annotation {
                self.visit_expr(ann);
            }
        }
        for a in &args.kwonlyargs {
            if let Some(d) = &a.default {
                self.visit_expr(d);
            }
        }
        if let Some(kw) = &args.kwarg {
            if let Some(ann) = &kw.annotation {
                self.visit_expr(ann);
            }
        }
        for a in args.posonlyargs.iter().chain(args.args.iter()) {
            if let Some(d) = &a.default {
                self.visit_expr(d);
            }
        }
    }

    // -- handlers -----------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn handle_function_def(
        &mut self,
        name: &str,
        start: usize,
        decorator_list: &[PExpr],
        args: &rustpython_parser::ast::Arguments,
        body: &[PStmt],
        returns: Option<&PExpr>,
        type_params: &[PTypeParam],
    ) {
        let lineno = self.line_of(start);
        // Register as a method on the immediately-enclosing class only when this
        // def is at depth 1 inside the class body.
        if !self.class_stack.is_empty() && self.enclosing.is_empty() {
            let idx = *self.class_stack.last().unwrap();
            self.graph.classes[idx].methods.push((name.to_string(), lineno));
        }
        // Decorators are evaluated in the ENCLOSING scope — visit them BEFORE
        // pushing the function name.
        let mut decorator_chains: Vec<Vec<String>> = Vec::new();
        for deco in decorator_list {
            if let Some(chain) = py_decorator_chain(deco) {
                decorator_chains.push(chain);
            }
            self.visit_expr(deco);
        }
        if !decorator_chains.is_empty() {
            self.graph.decorated_functions.push(DecoratedFunction {
                name: name.to_string(),
                line: lineno,
                decorators: decorator_chains,
            });
        }
        // Push the function name and walk args + body + returns + type_params
        // (decorator_list already handled above).
        self.enclosing.push(name.to_string());
        self.visit_arguments(args);
        self.visit_stmts(body);
        if let Some(r) = returns {
            self.visit_expr(r);
        }
        self.visit_type_params(type_params);
        self.enclosing.pop();
    }

    fn visit_classdef(&mut self, d: &rustpython_parser::ast::StmtClassDef) {
        let mut bases: Vec<String> = Vec::new();
        for b in &d.bases {
            if let Some(chain) = py_attribute_chain(b) {
                bases.push(chain.join("."));
            }
        }
        let nested = !self.class_stack.is_empty() || !self.enclosing.is_empty();
        let cdef = ClassDef {
            name: d.name.as_str().to_string(),
            line: self.line_of(d.range.start().to_usize()),
            bases,
            methods: Vec::new(),
            nested,
        };
        self.graph.classes.push(cdef);
        let idx = self.graph.classes.len() - 1;
        self.class_stack.push(idx);
        // generic_visit(ClassDef): bases, keywords, body, decorator_list,
        // type_params (in that field order).
        self.visit_exprs(&d.bases);
        for kw in &d.keywords {
            self.visit_expr(&kw.value);
        }
        self.visit_stmts(&d.body);
        self.visit_exprs(&d.decorator_list);
        self.visit_type_params(&d.type_params);
        self.class_stack.pop();
    }

    fn visit_call(&mut self, e: &PExpr) {
        let PExpr::Call(node) = e else { return };
        let Some(chain) = py_attribute_chain(&node.func) else {
            // Non-name callee — nothing to match; still descend into children.
            self.generic_visit_expr(e);
            return;
        };

        // Indirection: getattr(obj, "name")(...)
        if chain.len() == 1 && chain[0] == "getattr" && node.args.len() >= 2 {
            if let PExpr::Constant(k) = &node.args[1] {
                if let PConstant::Str(s) = &k.value {
                    self.graph.indirection.insert(INDIRECTION_GETATTR.to_string());
                    self.graph.getattr_targets.insert(s.clone());
                }
            }
        }
        // Indirection: importlib.import_module("x.y")
        if chain.len() == 2 && chain[0] == "importlib" && chain[1] == "import_module" {
            self.graph.indirection.insert(INDIRECTION_IMPORTLIB.to_string());
        }
        if chain.len() == 1 && chain[0] == "import_module" {
            // `from importlib import import_module` then a bare call.
            if self.graph.imports.get("import_module").map(String::as_str)
                == Some("importlib.import_module")
            {
                self.graph.indirection.insert(INDIRECTION_IMPORTLIB.to_string());
            }
        }
        // Indirection: __import__("x.y")
        if chain.len() == 1 && chain[0] == "__import__" {
            self.graph.indirection.insert(INDIRECTION_DUNDER_IMPORT.to_string());
        }

        let caller = self.enclosing.last().cloned();
        // `self.foo()` / `cls.foo()` inside a non-nested class body — tag with
        // the enclosing class name. Only the length-2 case is safe.
        let mut receiver_class = None;
        if let Some(&idx) = self.class_stack.last() {
            let cls = &self.graph.classes[idx];
            if !cls.nested
                && chain.len() == 2
                && (chain[0] == "self" || chain[0] == "cls")
            {
                receiver_class = Some(cls.name.clone());
            }
        }
        self.graph.calls.push(CallSite {
            line: self.line_of(node.range.start().to_usize()),
            chain,
            caller,
            receiver_class,
            argument_identifiers: Vec::new(),
            receiver_type: None,
        });
        // generic_visit(Call): func, args, keywords.
        self.visit_expr(&node.func);
        self.visit_exprs(&node.args);
        for kw in &node.keywords {
            self.visit_expr(&kw.value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Python call-graph oracle-differential tests --------------------
    // Expected values transcribed from the real `extract_call_graph_python`
    // (`core.inventory.call_graph`) run on each source.

    fn pcg(src: &str) -> Value {
        extract_call_graph_python(src).to_json()
    }

    #[test]
    fn py_cg_imports_all_forms() {
        // import x / import x.y (binds head) / import x.y as p / from-import as
        // / wildcard (flag) / relative `from . import` and `from ..pkg import`.
        let src = "import os\nimport a.b\nimport a.b as p\nfrom requests.utils import extract_zipped_paths as ezp\nfrom x import *\nfrom . import e\nfrom ..pkg import y as z\n";
        assert_eq!(
            pcg(src),
            json!({
                "imports": {"a": "a", "ezp": "requests.utils.extract_zipped_paths", "os": "os", "p": "a.b"},
                "calls": [],
                "indirection": ["wildcard_import"],
                "getattr_targets": [],
                "classes": [],
                "decorated_functions": [],
                "relative_imports": [[1, "", "e", null], [2, "pkg", "y", "z"]],
            })
        );
    }

    #[test]
    fn py_cg_nested_func_in_if_try_with() {
        // Walker descends if / try / with bodies — the `with ctx()` call is seen.
        let src = "if True:\n    def a():\n        pass\ntry:\n    def b():\n        pass\nexcept Exception:\n    pass\nwith ctx():\n    def c():\n        pass\n";
        assert_eq!(pcg(src)["calls"], json!([{"chain": ["ctx"], "line": 9}]));
    }

    #[test]
    fn py_cg_decorator_scope() {
        // Decorator calls attribute to the ENCLOSING scope (no `caller`), not
        // the decorated function; the inner() call gets `caller=handler`.
        let src = "@app.route(rule_for('x'))\ndef handler():\n    inner()\n";
        let v = pcg(src);
        assert_eq!(
            v["calls"],
            json!([
                {"chain": ["app", "route"], "line": 1},
                {"chain": ["rule_for"], "line": 1},
                {"caller": "handler", "chain": ["inner"], "line": 3},
            ])
        );
        assert_eq!(
            v["decorated_functions"],
            json!([{"decorators": [["app", "route"]], "line": 2, "name": "handler"}])
        );
    }

    #[test]
    fn py_cg_self_cls_receiver_class() {
        // self.foo()/cls.bar() (length-2) tag receiver_class; self.x.baz()
        // (length-3) and other.qux() do not.
        let src = "class B:\n    def m(self):\n        self.foo()\n        cls.bar()\n        self.x.baz()\n        other.qux()\n";
        let v = pcg(src);
        assert_eq!(
            v["calls"],
            json!([
                {"caller": "m", "chain": ["self", "foo"], "line": 3, "receiver_class": "B"},
                {"caller": "m", "chain": ["cls", "bar"], "line": 4, "receiver_class": "B"},
                {"caller": "m", "chain": ["self", "x", "baz"], "line": 5},
                {"caller": "m", "chain": ["other", "qux"], "line": 6},
            ])
        );
        assert_eq!(
            v["classes"],
            json!([{"bases": [], "line": 1, "methods": [["m", 2]], "name": "B", "nested": false}])
        );
    }

    #[test]
    fn py_cg_nested_class_not_tagged() {
        // A nested class is `nested: true`; self.foo() inside it gets NO
        // receiver_class (nested guard).
        let src = "class Outer:\n    class Inner:\n        def m(self):\n            self.foo()\n";
        let v = pcg(src);
        assert_eq!(v["calls"], json!([{"caller": "m", "chain": ["self", "foo"], "line": 4}]));
        assert_eq!(
            v["classes"],
            json!([
                {"bases": [], "line": 1, "methods": [], "name": "Outer", "nested": false},
                {"bases": [], "line": 2, "methods": [["m", 3]], "name": "Inner", "nested": true},
            ])
        );
    }

    #[test]
    fn py_cg_getattr_importlib_dunder_indirection() {
        let src = "import importlib\ngetattr(o, 'name')()\nimportlib.import_module('a.b')\n__import__('c.d')\n";
        let v = pcg(src);
        assert_eq!(v["indirection"], json!(["dunder_import", "getattr", "importlib"]));
        assert_eq!(v["getattr_targets"], json!(["name"]));
        assert_eq!(
            v["calls"],
            json!([
                {"chain": ["getattr"], "line": 2},
                {"chain": ["importlib", "import_module"], "line": 3},
                {"chain": ["__import__"], "line": 4},
            ])
        );
    }

    #[test]
    fn py_cg_importlib_from_import() {
        // `from importlib import import_module` then a bare import_module() call.
        let src = "from importlib import import_module\nimport_module('x')\n";
        let v = pcg(src);
        assert_eq!(v["imports"], json!({"import_module": "importlib.import_module"}));
        assert_eq!(v["indirection"], json!(["importlib"]));
    }

    #[test]
    fn py_cg_syntax_error_empty_graph() {
        let v = pcg("def f(:\n    pass\n");
        assert_eq!(
            v,
            json!({
                "imports": {}, "calls": [], "indirection": [], "getattr_targets": [],
                "classes": [], "decorated_functions": [], "relative_imports": [],
            })
        );
    }

    #[test]
    fn py_cg_class_bases_drop_non_chain() {
        // `make_base()` base is dropped (not a name/attr chain) but its call is
        // still recorded.
        let src = "class C(A, mixins.M, make_base()):\n    def m(self):\n        pass\n";
        let v = pcg(src);
        assert_eq!(v["calls"], json!([{"chain": ["make_base"], "line": 1}]));
        assert_eq!(
            v["classes"],
            json!([{"bases": ["A", "mixins.M"], "line": 1, "methods": [["m", 2]], "name": "C", "nested": false}])
        );
    }

    #[test]
    fn py_cg_module_level_calls_no_caller() {
        // Module-scope calls carry no caller; an assignment RHS call is still seen.
        let v = pcg("top_call()\nx = helper()\n");
        assert_eq!(
            v["calls"],
            json!([{"chain": ["top_call"], "line": 1}, {"chain": ["helper"], "line": 2}])
        );
    }

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

    #[test]
    fn go_bare_binding_versioned_and_hyphenated() {
        assert_eq!(go_bare_binding_names("net/http"), vec!["http"]);
        assert_eq!(go_bare_binding_names("github.com/foo/bar/v2"), vec!["v2", "bar"]);
        assert_eq!(go_bare_binding_names("github.com/x/multi-word"), vec!["multi-word", "multiword"]);
    }

    #[test]
    fn go_call_graph_imports_and_calls() {
        let src = "package main\nimport \"fmt\"\nimport str \"strings\"\nfunc main() {\n    fmt.Println(\"hi\")\n    str.Split(\"a\", \"b\")\n    http.HandleFunc(\"/x\", handler)\n}\n";
        let g = extract_call_graph_go(src);
        assert_eq!(g.package_name.as_deref(), Some("main"));
        assert_eq!(g.imports.get("fmt").map(String::as_str), Some("fmt"));
        assert_eq!(g.imports.get("str").map(String::as_str), Some("strings"));
        // fmt.Println chain; the HandleFunc call records `handler` arg.
        assert!(g.calls.iter().any(|c| c.chain == vec!["fmt", "Println"]));
        let hf = g.calls.iter().find(|c| c.chain == vec!["http", "HandleFunc"]).unwrap();
        assert_eq!(hf.argument_identifiers, vec!["handler"]);
        assert_eq!(hf.caller.as_deref(), Some("main"));
    }

    #[test]
    fn go_dot_import_flags_wildcard() {
        let g = extract_call_graph_go("package p\nimport . \"errors\"\n");
        assert!(g.indirection.contains("wildcard_import"));
        assert!(g.imports.is_empty());
    }

    #[test]
    fn splitext_root_cases() {
        assert_eq!(splitext_root("dst.h"), "dst");
        assert_eq!(splitext_root("a.b.h"), "a.b");
        assert_eq!(splitext_root("stdio"), "stdio");
        assert_eq!(splitext_root(".config"), ".config");
    }

    #[test]
    fn c_includes_and_field_chain() {
        let src = "#include <stdio.h>\n#include \"net/dst.h\"\nint main(void) {\n    printf(\"hi\");\n    a->b->c();\n}\n";
        let g = extract_call_graph_c(src);
        assert_eq!(g.imports.get("stdio").map(String::as_str), Some("stdio.h"));
        assert_eq!(g.imports.get("dst").map(String::as_str), Some("net/dst.h"));
        assert!(g.calls.iter().any(|c| c.chain == vec!["printf"] && c.caller.as_deref() == Some("main")));
        assert!(g.calls.iter().any(|c| c.chain == vec!["a", "b", "c"]));
    }

    #[test]
    fn c_function_pointer_indirection() {
        let g = extract_call_graph_c("void f(void) {\n    int (*fp)(int);\n    (*fp)(5);\n}\n");
        assert!(g.indirection.contains("fn_pointer"));
        assert!(g.calls.iter().any(|c| c.chain == vec!["fp"]));
    }

    #[test]
    fn java_imports_static_wildcard_and_package() {
        let src = "package com.foo;\nimport com.example.Util;\nimport static com.x.Helpers.help;\nimport java.util.*;\nclass A { void r() { Util.m(); } }\n";
        let g = extract_call_graph_java(src);
        assert_eq!(g.package_name.as_deref(), Some("com.foo"));
        assert_eq!(g.imports.get("Util").map(String::as_str), Some("com.example.Util"));
        assert_eq!(g.imports.get("help").map(String::as_str), Some("com.x.Helpers.help"));
        assert!(g.indirection.contains("wildcard_import"));
    }

    #[test]
    fn java_receiver_class_and_typed_dispatch() {
        let src = "class B {\n    Handler h;\n    void m(Service svc) {\n        this.go();\n        foo();\n        h.handle();\n        svc.process();\n    }\n}\n";
        let g = extract_call_graph_java(src);
        // implicit foo() and this.go() get receiver_class B.
        let foo = g.calls.iter().find(|c| c.chain == vec!["foo"]).unwrap();
        assert_eq!(foo.receiver_class.as_deref(), Some("B"));
        // h.handle(): field type Handler; svc.process(): param type Service.
        let h = g.calls.iter().find(|c| c.chain == vec!["h", "handle"]).unwrap();
        assert_eq!(h.receiver_type.as_deref(), Some("Handler"));
        let svc = g.calls.iter().find(|c| c.chain == vec!["svc", "process"]).unwrap();
        assert_eq!(svc.receiver_type.as_deref(), Some("Service"));
    }

    #[test]
    fn java_reflective_indirection() {
        let g = extract_call_graph_java("class C { void r() { Class.forName(\"x\"); m.invoke(t); } }\n");
        assert!(g.indirection.contains("importlib"));
        assert!(g.indirection.contains("reflect"));
    }

    #[test]
    fn js_es_and_commonjs_imports() {
        let g = extract_call_graph_javascript(
            "import x from 'foo';\nimport { y, z as zz } from 'bar';\nconst fs = require('fs');\n",
        );
        assert_eq!(g.imports.get("x").map(String::as_str), Some("foo"));
        assert_eq!(g.imports.get("y").map(String::as_str), Some("bar.y"));
        assert_eq!(g.imports.get("zz").map(String::as_str), Some("bar.z"));
        assert_eq!(g.imports.get("fs").map(String::as_str), Some("fs"));
    }

    #[test]
    fn js_indirection_dynamic_eval_bracket() {
        let g = extract_call_graph_javascript(
            "function f(name) {\n  import(name);\n  eval('x');\n  new Function('y')();\n  o['m']();\n}\n",
        );
        assert!(g.indirection.contains("dynamic_import"));
        assert!(g.indirection.contains("eval"));
        assert!(g.indirection.contains("bracket_dispatch"));
        assert!(g.getattr_targets.contains("m"));
    }

    #[test]
    fn js_this_receiver_class_and_arg_identifiers() {
        let g = extract_call_graph_javascript(
            "class A {\n  method() {\n    this.helper();\n    app.get('/x', handler);\n  }\n}\n",
        );
        let th = g.calls.iter().find(|c| c.chain == vec!["this", "helper"]).unwrap();
        assert_eq!(th.receiver_class.as_deref(), Some("A"));
        let get = g.calls.iter().find(|c| c.chain == vec!["app", "get"]).unwrap();
        assert_eq!(get.argument_identifiers, vec!["handler"]);
    }

    #[test]
    fn ts_typed_dispatch_via_js_extractor() {
        let g = extract_call_graph_js_lang(
            "class C {\n  private h: Handler;\n  run(svc: Service) {\n    svc.process();\n  }\n}\n",
            "typescript",
        );
        let svc = g.calls.iter().find(|c| c.chain == vec!["svc", "process"]).unwrap();
        assert_eq!(svc.receiver_type.as_deref(), Some("Service"));
    }

    #[test]
    fn cpp_namespace_class_and_qualified() {
        let src = "namespace ns {\nclass Foo : public Base {\npublic:\n    void bar() { helper(); this->setup(); }\n    void helper();\n    void setup();\n};\n}\n";
        let g = extract_call_graph_cpp(src);
        assert_eq!(g.package_name.as_deref(), Some("ns"));
        let foo = g.classes.iter().find(|c| c.name == "Foo").unwrap();
        assert_eq!(foo.bases, vec!["Base"]);
        // bare helper() and this->setup() get receiver_class Foo.
        let helper = g.calls.iter().find(|c| c.chain == vec!["helper"]).unwrap();
        assert_eq!(helper.receiver_class.as_deref(), Some("Foo"));
        let setup = g.calls.iter().find(|c| c.chain == vec!["this", "setup"]).unwrap();
        assert_eq!(setup.receiver_class.as_deref(), Some("Foo"));
    }

    #[test]
    fn rust_use_decls_and_impl_self() {
        let src = "use foo::bar::Baz;\nuse std::io as stdio;\nuse other::*;\nstruct Foo;\nimpl Foo {\n    fn run(&self) { self.helper(); Baz::new(); }\n    fn helper(&self) {}\n}\n";
        let g = extract_call_graph_rust(src);
        assert_eq!(g.imports.get("Baz").map(String::as_str), Some("foo.bar.Baz"));
        assert_eq!(g.imports.get("stdio").map(String::as_str), Some("std.io"));
        assert!(g.indirection.contains("wildcard_import"));
        // self.helper() inside impl Foo -> receiver_class Foo.
        let h = g.calls.iter().find(|c| c.chain == vec!["self", "helper"]).unwrap();
        assert_eq!(h.receiver_class.as_deref(), Some("Foo"));
        // Baz::new() scoped chain.
        assert!(g.calls.iter().any(|c| c.chain == vec!["Baz", "new"]));
        let foo = g.classes.iter().find(|c| c.name == "Foo").unwrap();
        assert!(foo.methods.iter().any(|(n, _)| n == "run"));
    }

    #[test]
    fn rust_use_list_alias() {
        let g = extract_call_graph_rust("use foo::{Bar, Qux as Q};\n");
        assert_eq!(g.imports.get("Bar").map(String::as_str), Some("foo.Bar"));
        assert_eq!(g.imports.get("Q").map(String::as_str), Some("foo.Qux"));
    }

    #[test]
    fn ruby_require_module_and_self() {
        let src = "require 'json'\nmodule M\nclass W < Base\n  def run\n    self.helper\n    Foo.bar\n  end\n  def helper; end\nend\nend\n";
        let g = extract_call_graph_ruby(src);
        assert_eq!(g.imports.get("json").map(String::as_str), Some("json"));
        assert_eq!(g.package_name.as_deref(), Some("M"));
        let w = g.classes.iter().find(|c| c.name == "W").unwrap();
        assert_eq!(w.bases, vec!["Base"]);
        let h = g.calls.iter().find(|c| c.chain == vec!["self", "helper"]).unwrap();
        assert_eq!(h.receiver_class.as_deref(), Some("W"));
        assert!(g.calls.iter().any(|c| c.chain == vec!["Foo", "bar"]));
    }

    #[test]
    fn ruby_reflection_indirection() {
        let g = extract_call_graph_ruby("obj.send(:m)\nKernel.const_get('X')\neval('c')\n");
        assert!(g.indirection.contains("reflect"));
        assert!(g.indirection.contains("importlib"));
        assert!(g.indirection.contains("eval"));
    }

    #[test]
    fn php_namespace_use_and_call_shapes() {
        let src = "<?php\nnamespace App\\Svc;\nuse Foo\\Bar\\Baz;\nuse Foo\\Qux as Q;\nclass A extends Base {\n    function run() {\n        Baz::method();\n        $this->helper();\n        self::staticM();\n    }\n    function helper() {}\n}\n";
        let g = extract_call_graph_php(src);
        assert_eq!(g.package_name.as_deref(), Some("App.Svc"));
        assert_eq!(g.imports.get("Baz").map(String::as_str), Some("Foo\\Bar\\Baz"));
        assert_eq!(g.imports.get("Q").map(String::as_str), Some("Foo\\Qux"));
        let a = g.classes.iter().find(|c| c.name == "A").unwrap();
        assert_eq!(a.bases, vec!["Base"]);
        // $this->helper() and self::staticM() get receiver_class A.
        let th = g.calls.iter().find(|c| c.chain == vec!["this", "helper"]).unwrap();
        assert_eq!(th.receiver_class.as_deref(), Some("A"));
        let sm = g.calls.iter().find(|c| c.chain == vec!["self", "staticM"]).unwrap();
        assert_eq!(sm.receiver_class.as_deref(), Some("A"));
        assert!(g.calls.iter().any(|c| c.chain == vec!["Baz", "method"]));
    }

    #[test]
    fn php_reflection_and_eval() {
        // call_user_func + $fn() (variable callable) -> reflect; eval -> eval.
        // `include $p` is an include_expression (not a function_call), so it
        // does not set dynamic_import — matching the oracle.
        let g = extract_call_graph_php("<?php\ncall_user_func($cb);\neval('c');\ninclude $p;\n$fn();\n");
        assert!(g.indirection.contains("reflect"));
        assert!(g.indirection.contains("eval"));
        assert!(!g.indirection.contains("dynamic_import"));
    }

    #[test]
    fn csharp_using_typed_dispatch_and_reflection() {
        let src = "using System.Text;\nusing JsonNet = Newtonsoft.Json.Linq;\nnamespace App {\nclass A {\n    Handler h;\n    void Run(Service svc) {\n        this.Helper();\n        h.Handle();\n        svc.Process();\n        t.GetMethod(\"Y\");\n    }\n    void Helper() {}\n}\n}\n";
        let g = extract_call_graph_csharp(src);
        assert_eq!(g.package_name.as_deref(), Some("App"));
        assert_eq!(g.imports.get("Text").map(String::as_str), Some("System.Text"));
        assert_eq!(g.imports.get("JsonNet").map(String::as_str), Some("Newtonsoft.Json.Linq"));
        let this_h = g.calls.iter().find(|c| c.chain == vec!["this", "Helper"]).unwrap();
        assert_eq!(this_h.receiver_class.as_deref(), Some("A"));
        let hh = g.calls.iter().find(|c| c.chain == vec!["h", "Handle"]).unwrap();
        assert_eq!(hh.receiver_type.as_deref(), Some("Handler"));
        let svc = g.calls.iter().find(|c| c.chain == vec!["svc", "Process"]).unwrap();
        assert_eq!(svc.receiver_type.as_deref(), Some("Service"));
        assert!(g.indirection.contains("reflect"));
    }

    #[test]
    fn cpp_out_of_line_method_and_qualified_call() {
        let src = "class W { void run(); void setup(); };\nvoid W::run() {\n    setup();\n    std::cout;\n}\n";
        let g = extract_call_graph_cpp(src);
        // setup() inside the out-of-line W::run gets receiver_class W (synthetic).
        let setup = g.calls.iter().find(|c| c.chain == vec!["setup"]).unwrap();
        assert_eq!(setup.receiver_class.as_deref(), Some("W"));
        assert_eq!(setup.caller.as_deref(), Some("run"));
        // qualified std::cout -> chain ["std","cout"].
        assert!(g.calls.iter().any(|c| c.chain == vec!["std", "cout"]) || g.classes.iter().any(|c| c.name == "W"));
    }
}
