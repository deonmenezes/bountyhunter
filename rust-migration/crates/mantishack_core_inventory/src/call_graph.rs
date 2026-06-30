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

// Indirection flags (subset; grows as language extractors are ported).
const INDIRECTION_WILDCARD_IMPORT: &str = "wildcard_import";
const INDIRECTION_REFLECT: &str = "reflect";
const INDIRECTION_FN_POINTER: &str = "fn_pointer";
const INDIRECTION_IMPORTLIB: &str = "importlib";

const JAVA_TYPE_NODES: &[&str] =
    &["type_identifier", "scoped_type_identifier", "generic_type", "array_type"];

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
}
