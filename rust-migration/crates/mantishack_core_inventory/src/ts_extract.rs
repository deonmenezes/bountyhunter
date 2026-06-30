//! Tree-sitter function extraction — Rust port of the Python branch of
//! `TreeSitterExtractor` in `core/inventory/extractors.py`.
//!
//! This is the production extraction path (regex extractors are only a
//! fallback). Python is wired first; other languages are added as their
//! branches are ported. Output mirrors the Python `FunctionInfo.to_dict()`
//! shape exactly, quirks included — notably that a plain `identifier`
//! parameter is dropped (a leaf node has no `identifier` *child*, so
//! `_parse_param` finds no name), which is why `def foo(a, b=2)` yields the
//! signature `foo(b)`.

use std::sync::OnceLock;

use regex::Regex;
use rustpython_parser::ast::{
    Arguments, BoolOp, CmpOp, Comprehension, Constant as PConstant, Expr as PExpr, ExprBinOp,
    ExprBoolOp, ExprCompare, ExprUnaryOp, Operator, Stmt as PStmt, UnaryOp,
};
use rustpython_parser::Parse as _;
use tree_sitter::Node;

use crate::extractors::{CodeItem, PyLineIndex, KIND_FUNCTION, KIND_GLOBAL, KIND_TOP_LEVEL};

const ASSIGN_NODE_TYPES: &[&str] = &["assignment", "assignment_expression", "augmented_assignment"];
const CALL_NODE_TYPES: &[&str] = &["call", "call_expression"];

/// Security-relevant metadata extracted from a function definition. Mirrors the
/// Python `FunctionMetadata` dataclass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FunctionMetadata {
    pub class_name: Option<String>,
    pub visibility: Option<String>,
    pub attributes: Vec<String>,
    pub return_type: Option<String>,
    pub parameters: Vec<(String, Option<String>)>,
    pub class_attributes: Vec<String>,
}

/// A function or method in the inventory (`kind` is always `function`). Mirrors
/// the Python `FunctionInfo` dataclass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionInfo {
    pub name: String,
    pub kind: String,
    pub line_start: i64,
    pub line_end: Option<i64>,
    pub signature: Option<String>,
    pub metadata: Option<FunctionMetadata>,
    pub checked_by: Vec<String>,
}

/// Parameter-type node kinds recognised by `_parse_param`.
const TYPE_NODE_KINDS: &[&str] = &[
    "type",
    "type_identifier",
    "generic_type",
    "pointer_type",
    "array_type",
    "scoped_type_identifier",
    "type_annotation",
    "primitive_type",
    "sized_type_specifier",
];

/// Extract functions from `content` via tree-sitter, matching the Python
/// `TreeSitterExtractor.extract`. Returns an empty vec if the grammar isn't
/// wired or parsing fails (caller falls back), mirroring the Python behaviour.
/// Languages whose ITEM extraction the Python oracle drives through tree-sitter
/// (`_ts_language`). NOTE: rust + php are absent here — the Python extractor has
/// no rust/php grammar, so those fall through to the regex `GenericExtractor`.
/// Parity therefore requires the same regex path for them, NOT the (available)
/// tree-sitter grammar.
const TS_ITEM_LANGS: &[&str] =
    &["python", "java", "javascript", "typescript", "tsx", "c", "cpp", "go", "csharp", "ruby"];

pub fn extract_functions(language: &str, content: &str) -> Vec<FunctionInfo> {
    // Non-tree-sitter languages (rust/php/...) use the regex GenericExtractor,
    // matching the Python fallback when no grammar is available.
    if !TS_ITEM_LANGS.contains(&language) {
        return generic_extract(content);
    }
    let Some(tree) = mantishack_ts::parse(language, content) else {
        return Vec::new();
    };
    let src = content.as_bytes();
    let mut out: Vec<FunctionInfo> = Vec::new();
    walk(tree.root_node(), src, language, &mut out, None, &[]);
    out
}

fn generic_pat1() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:function|def|func|fn|sub)\s+(\w+)\s*\(").unwrap())
}

fn generic_pat2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\([^)]*\)\s*\{").unwrap())
}

/// Regex fallback extractor (`GenericExtractor`): first matching pattern per
/// line yields a function name; dedup by name across the file.
fn generic_extract(content: &str) -> Vec<FunctionInfo> {
    let mut out: Vec<FunctionInfo> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (i, line) in content.split('\n').enumerate() {
        let line_no = (i + 1) as i64;
        for re in [generic_pat1(), generic_pat2()] {
            if let Some(caps) = re.captures(line) {
                let name = caps[1].to_string();
                if seen.insert(name.clone()) {
                    out.push(FunctionInfo {
                        name,
                        kind: KIND_FUNCTION.to_string(),
                        line_start: line_no,
                        line_end: None,
                        signature: None,
                        metadata: None,
                        checked_by: Vec::new(),
                    });
                }
                break;
            }
        }
    }
    out
}

/// Python convenience wrapper (kept for the existing call sites/tests).
pub fn extract_python_functions(content: &str) -> Vec<FunctionInfo> {
    extract_functions("python", content)
}

/// JavaScript convenience wrapper.
pub fn extract_javascript_functions(content: &str) -> Vec<FunctionInfo> {
    extract_functions("javascript", content)
}

/// C convenience wrapper.
pub fn extract_c_functions(content: &str) -> Vec<FunctionInfo> {
    extract_functions("c", content)
}

/// Go convenience wrapper.
pub fn extract_go_functions(content: &str) -> Vec<FunctionInfo> {
    extract_functions("go", content)
}

/// Java convenience wrapper.
pub fn extract_java_functions(content: &str) -> Vec<FunctionInfo> {
    extract_functions("java", content)
}

fn is_js_family(language: &str) -> bool {
    matches!(language, "javascript" | "typescript" | "tsx")
}

/// Node types that represent functions/methods per language (`_FUNC_TYPES`).
fn func_types(language: &str) -> &'static [&'static str] {
    match language {
        "python" => &["function_definition"],
        "javascript" | "typescript" | "tsx" => {
            &["function_declaration", "method_definition", "arrow_function"]
        }
        "c" | "cpp" => &["function_definition"],
        "go" => &["function_declaration", "method_declaration"],
        "java" => &["method_declaration", "constructor_declaration"],
        "csharp" | "c_sharp" => {
            &["method_declaration", "constructor_declaration", "local_function_statement"]
        }
        "ruby" => &["method", "singleton_method"],
        _ => &[],
    }
}

/// Node types that represent classes per language (`_CLASS_TYPES`).
fn class_types(language: &str) -> &'static [&'static str] {
    match language {
        "python" => &["class_definition"],
        "javascript" => &["class_declaration"],
        "typescript" | "tsx" => &["class_declaration", "abstract_class_declaration"],
        "java" => &["class_declaration", "interface_declaration"],
        "csharp" | "c_sharp" => {
            &["class_declaration", "interface_declaration", "struct_declaration", "record_declaration"]
        }
        "ruby" => &["class", "module"],
        _ => &[],
    }
}

/// Sibling node types allowed between a JS/TS decorator and its declaration.
const TS_DECORATOR_SKIP: &[&str] = &[
    "export", "default", "abstract", "async", "static", "readonly",
    "accessibility_modifier", "comment", "override",
];

fn children<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).collect()
}

fn text<'a>(node: Node<'a>, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn walk(
    node: Node,
    src: &[u8],
    language: &str,
    out: &mut Vec<FunctionInfo>,
    class_name: Option<&str>,
    class_attributes: &[String],
) {
    let fts = func_types(language);
    let cts = class_types(language);
    for child in children(node) {
        let k = child.kind();
        if cts.contains(&k) {
            let cname = get_name(child, src, language);
            // class_attributes = ts_decorators (JS/TS) + class_annotations.
            let mut cattrs = ts_decorators(child, src, language);
            cattrs.extend(class_annotations(child, src));
            walk(child, src, language, out, cname.as_deref(), &cattrs);
        } else if k == "public_field_definition" {
            // TS class property holding an arrow/function (handler = (x) => {…}).
            if let Some(arrow) = find_child(child, &["arrow_function", "function"]) {
                if let Some(name) = get_name(child, src, language) {
                    out.push(FunctionInfo {
                        name,
                        kind: KIND_FUNCTION.to_string(),
                        line_start: child.start_position().row as i64 + 1,
                        line_end: Some(child.end_position().row as i64 + 1),
                        signature: Some(sig_from_text(child, src)),
                        metadata: Some(FunctionMetadata {
                            class_name: class_name.map(str::to_string),
                            visibility: ts_member_visibility(child, src, language),
                            attributes: ts_decorators(child, src, language),
                            parameters: extract_parameters(arrow, src, language),
                            class_attributes: class_attributes.to_vec(),
                            ..Default::default()
                        }),
                        checked_by: Vec::new(),
                    });
                }
            }
            walk(child, src, language, out, class_name, class_attributes);
        } else if matches!(k, "lexical_declaration" | "variable_declaration") {
            walk(child, src, language, out, class_name, class_attributes);
        } else if k == "variable_declarator" {
            // JS/TS: const f = () => {} / const g = function() {}
            if let Some(arrow) = find_child(child, &["arrow_function", "function"]) {
                if let Some(name) = get_name(child, src, language) {
                    let exported = child
                        .parent()
                        .and_then(|p| p.parent())
                        .is_some_and(|gp| gp.kind() == "export_statement");
                    out.push(FunctionInfo {
                        name,
                        kind: KIND_FUNCTION.to_string(),
                        line_start: child.start_position().row as i64 + 1,
                        line_end: Some(child.end_position().row as i64 + 1),
                        signature: Some(sig_from_text(child, src)),
                        metadata: Some(FunctionMetadata {
                            class_name: class_name.map(str::to_string),
                            visibility: if exported { Some("exported".to_string()) } else { None },
                            parameters: extract_parameters(arrow, src, language),
                            ..Default::default()
                        }),
                        checked_by: Vec::new(),
                    });
                }
                // arrow found → do not recurse (matches the Python `continue`).
            } else {
                walk(child, src, language, out, class_name, class_attributes);
            }
        } else if fts.contains(&k) {
            // JS/TS decorators are preceding siblings; Python uses a
            // decorated_definition wrapper. C# methods also carry [Attr]s.
            let mut attrs = ts_decorators(child, src, language);
            attrs.extend(csharp_attributes(child, src, language));
            let mut fnode = child;
            if let Some(parent) = child.parent() {
                if parent.kind() == "decorated_definition" {
                    for sib in children(parent) {
                        if sib.kind() == "decorator" {
                            attrs.push(lstrip_at(text(sib, src)));
                        }
                    }
                    fnode = find_child(parent, fts).unwrap_or(child);
                }
            }
            if let Some(fi) = extract_function(fnode, src, language, class_name, attrs, class_attributes)
            {
                out.push(fi);
            }
            walk(child, src, language, out, class_name, class_attributes);
        } else {
            // Includes `decorated_definition` (Python): walk into the wrapper;
            // the inner function_definition collects decorators via its parent.
            walk(child, src, language, out, class_name, class_attributes);
        }
    }
}

/// `str.lstrip("@")` — strip leading `@` only (no other whitespace).
fn lstrip_at(s: &str) -> String {
    s.trim_start_matches('@').to_string()
}

fn find_child<'a>(node: Node<'a>, types: &[&str]) -> Option<Node<'a>> {
    children(node).into_iter().find(|c| types.contains(&c.kind()))
}

/// `child.text[:200].split("{")[0].strip()` — the declarator's signature.
fn sig_from_text(node: Node, src: &[u8]) -> String {
    let t: String = text(node, src).chars().take(200).collect();
    t.split('{').next().unwrap_or("").trim().to_string()
}

/// JS/TS decorators on a class or method — preceding `decorator` siblings,
/// stored `@`-stripped. `[]` for non-JS-family languages (`_ts_decorators`).
fn ts_decorators(node: Node, src: &[u8], language: &str) -> Vec<String> {
    if !is_js_family(language) {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    let mut sib = node.prev_sibling();
    while let Some(s) = sib {
        if s.kind() == "decorator" {
            out.push(lstrip_at(text(s, src)).trim().to_string());
        } else if s.is_named() && !TS_DECORATOR_SKIP.contains(&s.kind()) {
            break;
        }
        sib = s.prev_sibling();
    }
    out.reverse();
    out
}

/// JS/TS class-member visibility (`accessibility_modifier`, default `public`);
/// `None` for non-JS-family languages (`_ts_member_visibility`).
fn ts_member_visibility(node: Node, src: &[u8], language: &str) -> Option<String> {
    if !is_js_family(language) {
        return None;
    }
    for child in children(node) {
        if child.kind() == "accessibility_modifier" {
            return Some(text(child, src).trim().to_string());
        }
    }
    Some("public".to_string())
}

/// Annotations declared on a class (Java `modifiers`, etc.). `[]` for
/// Python/JS classes (none of those nodes appear). Partial port of
/// `_class_annotations` — extended as Java/C#/Ruby are wired.
fn class_annotations(node: Node, src: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for child in children(node) {
        match child.kind() {
            "modifiers" => {
                for m in children(child) {
                    if matches!(m.kind(), "marker_annotation" | "annotation") {
                        out.push(lstrip_at(text(m, src)));
                    }
                }
            }
            // C#: `[Attr]` attributes on the class.
            "attribute_list" => csharp_attr_names(child, src, &mut out),
            // Ruby: `class X < Base` — base is a constant / scope_resolution.
            // Java: `extends Foo` — base is a type_identifier / generic_type.
            "superclass" => {
                for sc in children(child) {
                    if matches!(sc.kind(), "constant" | "scope_resolution") {
                        out.push(text(sc, src).to_string());
                    }
                }
                java_base_names(child, src, &mut out);
            }
            // Java: `implements Bar` / interface `extends Baz`.
            "super_interfaces" | "extends_interfaces" => {
                java_base_names(child, src, &mut out);
            }
            _ => {}
        }
    }
    out
}

/// Attribute names in one C# `attribute_list` (`[HttpGet, Route("x")]` ->
/// `["HttpGet", "Route"]`) — the leading identifier/qualified_name of each
/// `attribute` (`_csharp_attr_names`).
fn csharp_attr_names(node: Node, src: &[u8], out: &mut Vec<String>) {
    for a in children(node) {
        if a.kind() != "attribute" {
            continue;
        }
        for ac in children(a) {
            if matches!(ac.kind(), "identifier" | "qualified_name") {
                out.push(text(ac, src).to_string());
                break;
            }
        }
    }
}

/// C# attributes on a method/ctor — its `attribute_list` children
/// (`_csharp_attributes`).
fn csharp_attributes(node: Node, src: &[u8], language: &str) -> Vec<String> {
    let mut out = Vec::new();
    if matches!(language, "csharp" | "c_sharp") {
        for child in children(node) {
            if child.kind() == "attribute_list" {
                csharp_attr_names(child, src, &mut out);
            }
        }
    }
    out
}

/// Append base type tail-names from a Java `superclass`/`super_interfaces`
/// node (`JpaRepository<Owner,Integer>` -> `JpaRepository`; `org.x.Validator`
/// -> `Validator`). A `type_list` separates multiple bases.
fn java_base_names(node: Node, src: &[u8], out: &mut Vec<String>) {
    const TYPE_NODES: &[&str] = &["type_identifier", "scoped_type_identifier", "generic_type"];
    fn add(tn: Node, src: &[u8], out: &mut Vec<String>) {
        let base = text(tn, src)
            .split('<')
            .next()
            .unwrap_or("")
            .trim()
            .split('.')
            .next_back()
            .unwrap_or("")
            .trim();
        if !base.is_empty() {
            out.push(base.to_string());
        }
    }
    for n in children(node) {
        if n.kind() == "type_list" {
            for tn in children(n) {
                if TYPE_NODES.contains(&tn.kind()) {
                    add(tn, src, out);
                }
            }
        } else if TYPE_NODES.contains(&n.kind()) {
            add(n, src, out);
        }
    }
}

/// Extract visibility and (possibly updated) class_name. Python branch returns
/// `(None, class_name)`; JS sets member visibility for `method_definition` and
/// `exported` for an `export_statement` parent (`_extract_visibility`).
fn extract_visibility(
    node: Node,
    src: &[u8],
    language: &str,
    name: &str,
    class_name: Option<&str>,
    attrs: &mut Vec<String>,
) -> (Option<String>, Option<String>) {
    let mut visibility = None;
    let mut class_name_out = class_name.map(str::to_string);
    if node.kind() == "method_definition" {
        visibility = ts_member_visibility(node, src, language);
    }
    // C#: `modifier` children carry access keywords; members default to private.
    if matches!(language, "csharp" | "c_sharp")
        && matches!(node.kind(), "method_declaration" | "constructor_declaration")
    {
        visibility = Some("private".to_string());
        for child in children(node) {
            if child.kind() == "modifier" {
                let t = text(child, src);
                if matches!(t, "public" | "private" | "protected" | "internal") {
                    visibility = Some(t.to_string());
                    break;
                }
            }
        }
    }

    // Java: the `modifiers` block holds annotations (-> attributes) and access
    // keywords (-> visibility); `static` is appended to the access keyword.
    for child in children(node) {
        if child.kind() == "modifiers" {
            for m in children(child) {
                match m.kind() {
                    "marker_annotation" | "annotation" => attrs.push(lstrip_at(text(m, src))),
                    "public" | "private" | "protected" => {
                        visibility = Some(text(m, src).to_string());
                    }
                    "static" => {
                        let base = visibility.take().unwrap_or_default();
                        visibility = Some(format!("{base} static").trim().to_string());
                    }
                    _ => {}
                }
            }
        }
    }

    // C/C++: storage-class linkage. `extern` (external linkage) takes priority
    // over `static` (internal linkage); a following `inline` must not mask it.
    let specs: Vec<&str> = children(node)
        .iter()
        .filter(|c| c.kind() == "storage_class_specifier")
        .map(|c| text(*c, src))
        .collect();
    if specs.contains(&"extern") {
        visibility = Some("extern".to_string());
    } else if specs.contains(&"static") {
        visibility = Some("static".to_string());
    }

    // Go: exported from a capitalised name; the receiver param_list (which
    // precedes the method name) supplies class_name.
    if language == "go" {
        if first_isupper(name) {
            visibility = Some("exported".to_string());
        }
        let kids = children(node);
        let name_byte = kids.iter().find_map(|c| {
            if c.kind() == "field_identifier" || (c.kind() == "identifier" && text(*c, src) == name) {
                Some(c.start_byte())
            } else {
                None
            }
        });
        if let Some(nb) = name_byte {
            for child in &kids {
                if child.kind() == "parameter_list" && child.start_byte() < nb {
                    let recv = text(*child, src).trim_matches(|c| c == '(' || c == ')');
                    if let Some(last) = recv.split_whitespace().last() {
                        class_name_out = Some(last.trim_start_matches('*').to_string());
                    }
                }
            }
        }
    }

    if let Some(parent) = node.parent() {
        if parent.kind() == "export_statement" {
            visibility = Some("exported".to_string());
        }
    }
    (visibility, class_name_out)
}

/// The first `identifier`/`name`/`property_identifier` (and class-decl-only
/// `constant`/`type_identifier`) child. Python/JS subset of `_get_name`;
/// C/Go/Java/C++ branches are added as those languages are wired.
fn get_name(node: Node, src: &[u8], _language: &str) -> Option<String> {
    let is_class_decl = matches!(
        node.kind(),
        "class_declaration" | "abstract_class_declaration" | "interface_declaration" | "class" | "module"
    );
    for child in children(node) {
        match child.kind() {
            "identifier" | "name" => return Some(text(child, src).to_string()),
            "property_identifier" => return Some(text(child, src).to_string()),
            "constant" if is_class_decl => return Some(text(child, src).to_string()),
            "type_identifier" if is_class_decl => return Some(text(child, src).to_string()),
            // C/C++: the name is nested inside the (possibly pointer-wrapped)
            // function_declarator; field_identifier names in-class methods.
            "function_declarator" | "pointer_declarator" => {
                return get_name(child, src, _language)
            }
            "field_identifier" => return Some(text(child, src).to_string()),
            "parenthesized_declarator" => {
                if let Some(inner) = get_name(child, src, _language) {
                    return Some(inner);
                }
            }
            _ => {}
        }
    }
    None
}

fn extract_function(
    node: Node,
    src: &[u8],
    language: &str,
    class_name: Option<&str>,
    mut attrs: Vec<String>,
    class_attributes: &[String],
) -> Option<FunctionInfo> {
    let name = get_name(node, src, language)?;
    let (visibility, class_name) =
        extract_visibility(node, src, language, &name, class_name, &mut attrs);
    let parameters = extract_parameters(node, src, language);
    let return_type = extract_return_type(node, src);

    let param_strs: Vec<String> = parameters
        .iter()
        .map(|(n, t)| match t {
            Some(t) => format!("{n}: {t}"),
            None => n.clone(),
        })
        .collect();
    let mut sig = format!("{name}({})", param_strs.join(", "));
    if let Some(rt) = &return_type {
        sig.push_str(&format!(" -> {rt}"));
    }
    let sig: String = sig.chars().take(200).collect();

    Some(FunctionInfo {
        name,
        kind: KIND_FUNCTION.to_string(),
        line_start: node.start_position().row as i64 + 1,
        line_end: Some(node.end_position().row as i64 + 1),
        signature: Some(sig),
        metadata: Some(FunctionMetadata {
            class_name,
            visibility,
            attributes: attrs,
            return_type,
            parameters,
            class_attributes: class_attributes.to_vec(),
        }),
        checked_by: Vec::new(),
    })
}

fn extract_parameters(node: Node, src: &[u8], language: &str) -> Vec<(String, Option<String>)> {
    let mut params: Vec<(String, Option<String>)> = Vec::new();
    for child in children(node) {
        if matches!(child.kind(), "parameters" | "formal_parameters" | "parameter_list") {
            for param in children(child) {
                if let (Some(name), ptype) = parse_param(param, src, language) {
                    if !matches!(name.as_str(), "(" | ")" | "," | "self" | "this") {
                        params.push((name, ptype));
                    }
                }
            }
        }
        // C/C++: params are inside function_declarator → parameter_list. This
        // only recurses through a DIRECT function_declarator child, so a
        // pointer-return function (function_declarator nested in
        // pointer_declarator) yields no params — matching the Python quirk.
        if child.kind() == "function_declarator" {
            params.extend(extract_parameters(child, src, language));
        }
    }
    params
}

fn parse_param(node: Node, src: &[u8], language: &str) -> (Option<String>, Option<String>) {
    let mut name: Option<String> = None;
    let mut ptype: Option<String> = None;
    for child in children(node) {
        let k = child.kind();
        if matches!(k, "identifier" | "name") {
            name = Some(text(child, src).to_string());
        } else if TYPE_NODE_KINDS.contains(&k) {
            ptype = Some(lstrip_colon_space(text(child, src)));
        } else if k == "pointer_declarator" {
            // C: the pointer wraps the identifier; the type gains a `*`.
            name = get_name(child, src, language);
            if let Some(t) = ptype.take() {
                ptype = Some(format!("{t}*"));
            }
        }
    }
    // Fallback: parse the full text for typed params like "String data" /
    // "const char *buf" when no identifier child was found.
    if name.is_none() && matches!(node.kind(), "formal_parameter" | "parameter_declaration") {
        let t = text(node, src).trim().trim_end_matches(',').to_string();
        let spaced = t.replace('*', "* ");
        let parts: Vec<&str> = spaced.split_whitespace().collect();
        if parts.len() >= 2 {
            name = Some(parts[parts.len() - 1].trim_start_matches('*').to_string());
            ptype = Some(parts[..parts.len() - 1].join(" ").replace("  ", " "));
        }
    }
    // `if not name and ptype: name = "_anon"` (anonymous typed param).
    if name.is_none() && ptype.is_some() {
        name = Some("_anon".to_string());
    }
    (name, ptype)
}

/// `str.lstrip(": ")` — strip any leading `:` and space characters.
fn lstrip_colon_space(s: &str) -> String {
    s.trim_start_matches([':', ' ']).to_string()
}

fn extract_return_type(node: Node, src: &[u8]) -> Option<String> {
    let kids = children(node);
    // C/C++: the return type is a sibling before the function_declarator.
    let func_decl_pos = kids.iter().position(|c| c.kind() == "function_declarator");
    for (i, child) in kids.iter().enumerate() {
        if let Some(fp) = func_decl_pos {
            if i < fp
                && matches!(child.kind(), "primitive_type" | "type_identifier" | "sized_type_specifier")
            {
                return Some(text(*child, src).to_string());
            }
        }
        // Java/Python/Go: type after params.
        if matches!(child.kind(), "type" | "return_type") {
            return Some(lstrip_colon_space(text(*child, src)));
        }
        if func_decl_pos.is_none()
            && matches!(
                child.kind(),
                "type_identifier" | "generic_type" | "void_type" | "pointer_type" | "array_type"
            )
        {
            let params_seen = kids.iter().any(|c| {
                matches!(c.kind(), "parameters" | "formal_parameters" | "parameter_list")
                    && c.start_byte() < child.start_byte()
            });
            if params_seen {
                return Some(text(*child, src).to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Module-scope globals + top-level executable statements (Python branch).
// ---------------------------------------------------------------------------

/// `_ts_contains_call`: any `call`/`call_expression` within depth 5.
fn ts_contains_call(node: Node, depth: u32) -> bool {
    if CALL_NODE_TYPES.contains(&node.kind()) {
        return true;
    }
    if depth > 5 {
        return false;
    }
    children(node).into_iter().any(|c| ts_contains_call(c, depth + 1))
}

/// Languages whose extraction surfaces module-scope `top_level` items.
const TOP_LEVEL_LANGS: &[&str] = &["python", "javascript", "typescript", "tsx"];

/// Module-scope executable statements (run at import) as `top_level` items —
/// a root-level `expression_statement` containing a call but not an assignment.
/// Faithful port of `_extract_top_level_ts` (script-like languages only).
pub fn extract_top_level(language: &str, content: &str) -> Vec<CodeItem> {
    if !TOP_LEVEL_LANGS.contains(&language) {
        return Vec::new();
    }
    let Some(tree) = mantishack_ts::parse(language, content) else {
        return Vec::new();
    };
    let root = tree.root_node();
    let mut out: Vec<CodeItem> = Vec::new();
    for child in children(root) {
        if child.kind() != "expression_statement" {
            continue;
        }
        if children(child).iter().any(|c| ASSIGN_NODE_TYPES.contains(&c.kind())) {
            continue;
        }
        if ts_contains_call(child, 0) {
            let line = child.start_position().row as i64 + 1;
            out.push(CodeItem::new(
                format!("top_level:{line}"),
                KIND_TOP_LEVEL,
                line,
                Some(child.end_position().row as i64 + 1),
            ));
        }
    }
    out
}

/// Module-scope global variables/constants. Faithful port of
/// `_extract_globals_ts` for Python (UPPER/TitleCase assignments only, with
/// nested chained-assignment handling).
/// Node types that hold global declarations per language (`global_types`).
fn global_types(language: &str) -> &'static [&'static str] {
    match language {
        "python" => &["expression_statement", "assignment"],
        "javascript" | "typescript" | "tsx" => &["lexical_declaration", "variable_declaration"],
        "c" | "cpp" => &["declaration"],
        "java" => &["field_declaration"],
        "go" => &["var_declaration", "const_declaration"],
        _ => &[],
    }
}

/// Module-scope globals from a tree-sitter parse (`_extract_globals_ts`),
/// generalized over language. (Java's class-body scan is added with Java.)
pub fn extract_globals(language: &str, content: &str) -> Vec<CodeItem> {
    let target_types = global_types(language);
    if target_types.is_empty() {
        return Vec::new();
    }
    let Some(tree) = mantishack_ts::parse(language, content) else {
        return Vec::new();
    };
    let src = content.as_bytes();
    let root = tree.root_node();

    // Java field_declarations live inside class/interface/enum/record bodies,
    // not at the root — scan into those bodies. Other languages declare globals
    // at file scope.
    let scan_nodes: Vec<Node> = if language == "java" {
        let mut nodes = Vec::new();
        for top in children(root) {
            if matches!(
                top.kind(),
                "class_declaration" | "interface_declaration" | "enum_declaration" | "record_declaration"
            ) {
                if let Some(body) = children(top).into_iter().find(|c| {
                    matches!(c.kind(), "class_body" | "interface_body" | "enum_body" | "record_body")
                }) {
                    nodes.extend(children(body));
                }
            } else {
                nodes.push(top);
            }
        }
        nodes
    } else {
        children(root)
    };

    let mut out: Vec<CodeItem> = Vec::new();
    for child in scan_nodes {
        if !target_types.contains(&child.kind()) {
            continue;
        }
        for name in global_names(child, language, src) {
            out.push(CodeItem::new(
                name,
                KIND_GLOBAL,
                child.start_position().row as i64 + 1,
                Some(child.end_position().row as i64 + 1),
            ));
        }
    }
    out
}

/// Python globals convenience wrapper.
pub fn extract_python_globals(content: &str) -> Vec<CodeItem> {
    extract_globals("python", content)
}

/// Go globals convenience wrapper.
pub fn extract_go_globals(content: &str) -> Vec<CodeItem> {
    extract_globals("go", content)
}

/// Python top-level convenience wrapper (kept for existing tests).
pub fn extract_python_top_level(content: &str) -> Vec<CodeItem> {
    extract_top_level("python", content)
}

/// A single inventory item: either a function (rich `FunctionInfo`) or a
/// plain `CodeItem` (global / top-level / macro). Mirrors the Python
/// `extract_items` list, which mixes `FunctionInfo` and `CodeItem`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InventoryItem {
    Function(FunctionInfo),
    Item(CodeItem),
}

impl InventoryItem {
    pub fn kind(&self) -> &str {
        match self {
            Self::Function(f) => &f.kind,
            Self::Item(c) => &c.kind,
        }
    }

    pub fn line_start(&self) -> i64 {
        match self {
            Self::Function(f) => f.line_start,
            Self::Item(c) => c.line_start,
        }
    }

    pub fn line_end(&self) -> Option<i64> {
        match self {
            Self::Function(f) => f.line_end,
            Self::Item(c) => c.line_end,
        }
    }

    /// Serialize to the same shape as the Python `.to_dict()`.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Function(f) => function_info_to_json(f),
            Self::Item(c) => code_item_to_json(c),
        }
    }
}

fn code_item_to_json(c: &CodeItem) -> serde_json::Value {
    serde_json::json!({
        "name": c.name, "kind": c.kind, "line_start": c.line_start,
        "line_end": c.line_end, "checked_by": c.checked_by,
    })
}

fn function_info_to_json(f: &FunctionInfo) -> serde_json::Value {
    let mut d = serde_json::json!({
        "name": f.name, "kind": f.kind, "line_start": f.line_start,
        "line_end": f.line_end, "signature": f.signature, "checked_by": f.checked_by,
    });
    if let Some(m) = &f.metadata {
        let params: Vec<serde_json::Value> =
            m.parameters.iter().map(|(n, t)| serde_json::json!([n, t])).collect();
        d["metadata"] = serde_json::json!({
            "class_name": m.class_name, "visibility": m.visibility,
            "attributes": m.attributes, "return_type": m.return_type,
            "parameters": params, "class_attributes": m.class_attributes,
        });
    }
    d
}

/// Extract all inventory items (functions + globals + top-level + C/C++ macros)
/// from a file — port of `extract_items` for the tree-sitter path.
///
/// Faithful when tree-sitter yields functions: items = functions ++ globals ++
/// top-level ++ macros, in that order. For **Python**, when tree-sitter produced
/// zero `KIND_FUNCTION` items (or didn't parse), the `PythonExtractor` (`ast`)
/// path re-derives functions AND top-level items — dropping any tree-sitter
/// function/top-level items first (keeping globals) — exactly as the Python
/// orchestration does. The non-Python no-function regex fallback is still a
/// documented gap (out of scope here).
pub fn extract_items(language: &str, content: &str) -> Vec<InventoryItem> {
    let mut items: Vec<InventoryItem> = Vec::new();
    // Mirrors Python's `ts_parsed`: did tree-sitter construct + parse? For the
    // Python branch this is the only place the flag matters.
    let ts_parsed = TS_ITEM_LANGS.contains(&language) && mantishack_ts::parse(language, content).is_some();

    for f in extract_functions(language, content) {
        items.push(InventoryItem::Function(f));
    }
    for g in extract_globals(language, content) {
        items.push(InventoryItem::Item(g));
    }
    for t in extract_top_level(language, content) {
        items.push(InventoryItem::Item(t));
    }

    // Fallback (Python only): re-derive functions + top_level via the AST
    // extractor when tree-sitter produced no functions (or didn't parse). Drop
    // tree-sitter function/top_level items first; keep globals.
    let has_function = items.iter().any(|i| i.kind() == KIND_FUNCTION);
    if (!ts_parsed || !has_function) && language == "python" {
        items.retain(|i| i.kind() != KIND_FUNCTION && i.kind() != KIND_TOP_LEVEL);
        items.extend(python_ast_extract(content));
    }

    if matches!(language, "c" | "cpp") {
        for m in crate::extractors::extract_macros(content) {
            items.push(InventoryItem::Item(m));
        }
    }
    items
}

// ---------------------------------------------------------------------------
// Python AST extractor (`PythonExtractor`) + CPython-faithful `ast.unparse`.
// ---------------------------------------------------------------------------

/// AST-based Python function extraction with metadata — port of
/// `PythonExtractor.extract`. Returns functions (+ module-scope `top_level`
/// items) on success, or the regex fallback's functions on a parse error.
fn python_ast_extract(content: &str) -> Vec<InventoryItem> {
    match rustpython_parser::ast::Suite::parse(content, "<extractor>") {
        Ok(body) => {
            let lines = PyLineIndex::new(content);
            let mut out: Vec<InventoryItem> = Vec::new();
            py_extract_walk(&body, None, &lines, &mut out);
            out.extend(py_top_level_items(&body, &lines));
            out
        }
        Err(_) => py_regex_fallback(content),
    }
}

/// `PythonExtractor._walk`: collect functions with metadata, descending into
/// class/function bodies AND compound statements (if/try/with/for/while/match)
/// so nested functions are still captured. A `ClassDef` sets `class_name` for
/// its body; a `FunctionDef` keeps the current `class_name` for its body.
fn py_extract_walk(
    stmts: &[PStmt],
    class_name: Option<&str>,
    lines: &PyLineIndex,
    out: &mut Vec<InventoryItem>,
) {
    for s in stmts {
        match s {
            PStmt::ClassDef(c) => {
                py_extract_walk(&c.body, Some(c.name.as_str()), lines, out);
            }
            PStmt::FunctionDef(f) => {
                out.push(InventoryItem::Function(py_extract_function(s, class_name, lines)));
                py_extract_walk(&f.body, class_name, lines, out);
            }
            PStmt::AsyncFunctionDef(f) => {
                out.push(InventoryItem::Function(py_extract_function(s, class_name, lines)));
                py_extract_walk(&f.body, class_name, lines, out);
            }
            PStmt::If(n) => {
                py_extract_walk(&n.body, class_name, lines, out);
                py_extract_walk(&n.orelse, class_name, lines, out);
            }
            PStmt::For(n) => {
                py_extract_walk(&n.body, class_name, lines, out);
                py_extract_walk(&n.orelse, class_name, lines, out);
            }
            PStmt::AsyncFor(n) => {
                py_extract_walk(&n.body, class_name, lines, out);
                py_extract_walk(&n.orelse, class_name, lines, out);
            }
            PStmt::While(n) => {
                py_extract_walk(&n.body, class_name, lines, out);
                py_extract_walk(&n.orelse, class_name, lines, out);
            }
            PStmt::With(n) => py_extract_walk(&n.body, class_name, lines, out),
            PStmt::AsyncWith(n) => py_extract_walk(&n.body, class_name, lines, out),
            PStmt::Try(n) => {
                py_extract_walk(&n.body, class_name, lines, out);
                for h in &n.handlers {
                    let rustpython_parser::ast::ExceptHandler::ExceptHandler(eh) = h;
                    py_extract_walk(&eh.body, class_name, lines, out);
                }
                py_extract_walk(&n.orelse, class_name, lines, out);
                py_extract_walk(&n.finalbody, class_name, lines, out);
            }
            PStmt::TryStar(n) => {
                py_extract_walk(&n.body, class_name, lines, out);
                for h in &n.handlers {
                    let rustpython_parser::ast::ExceptHandler::ExceptHandler(eh) = h;
                    py_extract_walk(&eh.body, class_name, lines, out);
                }
                py_extract_walk(&n.orelse, class_name, lines, out);
                py_extract_walk(&n.finalbody, class_name, lines, out);
            }
            PStmt::Match(n) => {
                for case in &n.cases {
                    py_extract_walk(&case.body, class_name, lines, out);
                }
            }
            _ => {}
        }
    }
}

/// `PythonExtractor._extract_function`: build the signature (with `ast.unparse`
/// annotations / return type), parameters, return type and decorator metadata
/// for one `def`/`async def`. Uses `node.args.args` (regular positional args
/// only — posonly/vararg/kwonly/kwarg are excluded, matching CPython).
fn py_extract_function(s: &PStmt, class_name: Option<&str>, lines: &PyLineIndex) -> FunctionInfo {
    let (name, args, returns, decorator_list, is_async, start, end) = match s {
        PStmt::FunctionDef(d) => (
            d.name.as_str(),
            &d.args,
            d.returns.as_deref(),
            &d.decorator_list,
            false,
            d.range.start().to_usize(),
            d.range.end().to_usize(),
        ),
        PStmt::AsyncFunctionDef(d) => (
            d.name.as_str(),
            &d.args,
            d.returns.as_deref(),
            &d.decorator_list,
            true,
            d.range.start().to_usize(),
            d.range.end().to_usize(),
        ),
        _ => unreachable!("py_extract_function called on a non-def statement"),
    };

    let mut arg_strs: Vec<String> = Vec::new();
    for awd in &args.args {
        let mut sig = awd.def.arg.as_str().to_string();
        if let Some(ann) = &awd.def.annotation {
            sig.push_str(": ");
            sig.push_str(&py_unparse(ann));
        }
        arg_strs.push(sig);
    }
    let mut signature = format!("def {}({})", name, arg_strs.join(", "));
    if is_async {
        signature = format!("async {signature}");
    }
    if let Some(r) = returns {
        signature.push_str(" -> ");
        signature.push_str(&py_unparse(r));
    }

    let parameters: Vec<(String, Option<String>)> = args
        .args
        .iter()
        .map(|awd| (awd.def.arg.as_str().to_string(), awd.def.annotation.as_ref().map(|a| py_unparse(a))))
        .collect();
    let return_type = returns.map(py_unparse);
    let attributes: Vec<String> = decorator_list.iter().map(py_unparse).collect();

    FunctionInfo {
        name: name.to_string(),
        kind: KIND_FUNCTION.to_string(),
        line_start: lines.line_of(start),
        line_end: Some(lines.line_of(end.saturating_sub(1))),
        signature: Some(signature),
        metadata: Some(FunctionMetadata {
            class_name: class_name.map(|s| s.to_string()),
            visibility: None,
            attributes,
            return_type,
            parameters,
            class_attributes: Vec::new(),
        }),
        checked_by: Vec::new(),
    }
}

/// `PythonExtractor._top_level_items`: module-scope `Expr` statements whose
/// subtree contains a `Call` (e.g. `os.system(...)` at import time), emitted as
/// `top_level` CodeItems.
fn py_top_level_items(body: &[PStmt], lines: &PyLineIndex) -> Vec<InventoryItem> {
    let mut out: Vec<InventoryItem> = Vec::new();
    for s in body {
        if let PStmt::Expr(n) = s {
            if expr_contains_call(&n.value) {
                let line = lines.line_of(n.range.start().to_usize());
                let end = lines.line_of(n.range.end().to_usize().saturating_sub(1));
                let line_end = if end != 0 { end } else { line };
                out.push(InventoryItem::Item(CodeItem::new(
                    format!("top_level:{line}"),
                    KIND_TOP_LEVEL,
                    line,
                    Some(line_end),
                )));
            }
        }
    }
    out
}

/// `re.match(r'^(?:async\s+)?def\s+(\w+)\s*\(', line.strip())` per line — the
/// `PythonExtractor._regex_fallback` for unparseable files.
fn py_def_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?:async\s+)?def\s+(\w+)\s*\(").unwrap())
}

fn py_regex_fallback(content: &str) -> Vec<InventoryItem> {
    let re = py_def_re();
    let mut out: Vec<InventoryItem> = Vec::new();
    for (i, line) in content.split('\n').enumerate() {
        if let Some(caps) = re.captures(line.trim()) {
            out.push(InventoryItem::Function(FunctionInfo {
                name: caps[1].to_string(),
                kind: KIND_FUNCTION.to_string(),
                line_start: (i + 1) as i64,
                line_end: None,
                signature: None,
                metadata: None,
                checked_by: Vec::new(),
            }));
        }
    }
    out
}

/// True if `e` or any descendant expression is a `Call` (mirrors
/// `any(isinstance(n, ast.Call) for n in ast.walk(node))`).
fn expr_contains_call(e: &PExpr) -> bool {
    match e {
        PExpr::Call(_) => true,
        PExpr::BoolOp(n) => n.values.iter().any(expr_contains_call),
        PExpr::NamedExpr(n) => expr_contains_call(&n.target) || expr_contains_call(&n.value),
        PExpr::BinOp(n) => expr_contains_call(&n.left) || expr_contains_call(&n.right),
        PExpr::UnaryOp(n) => expr_contains_call(&n.operand),
        PExpr::Lambda(n) => expr_contains_call(&n.body) || arguments_contain_call(&n.args),
        PExpr::IfExp(n) => {
            expr_contains_call(&n.test) || expr_contains_call(&n.body) || expr_contains_call(&n.orelse)
        }
        PExpr::Dict(n) => {
            n.keys.iter().flatten().any(expr_contains_call) || n.values.iter().any(expr_contains_call)
        }
        PExpr::Set(n) => n.elts.iter().any(expr_contains_call),
        PExpr::ListComp(n) => expr_contains_call(&n.elt) || comps_contain_call(&n.generators),
        PExpr::SetComp(n) => expr_contains_call(&n.elt) || comps_contain_call(&n.generators),
        PExpr::GeneratorExp(n) => expr_contains_call(&n.elt) || comps_contain_call(&n.generators),
        PExpr::DictComp(n) => {
            expr_contains_call(&n.key) || expr_contains_call(&n.value) || comps_contain_call(&n.generators)
        }
        PExpr::Await(n) => expr_contains_call(&n.value),
        PExpr::Yield(n) => n.value.as_deref().is_some_and(expr_contains_call),
        PExpr::YieldFrom(n) => expr_contains_call(&n.value),
        PExpr::Compare(n) => {
            expr_contains_call(&n.left) || n.comparators.iter().any(expr_contains_call)
        }
        PExpr::FormattedValue(n) => {
            expr_contains_call(&n.value) || n.format_spec.as_deref().is_some_and(expr_contains_call)
        }
        PExpr::JoinedStr(n) => n.values.iter().any(expr_contains_call),
        PExpr::Attribute(n) => expr_contains_call(&n.value),
        PExpr::Subscript(n) => expr_contains_call(&n.value) || expr_contains_call(&n.slice),
        PExpr::Starred(n) => expr_contains_call(&n.value),
        PExpr::List(n) => n.elts.iter().any(expr_contains_call),
        PExpr::Tuple(n) => n.elts.iter().any(expr_contains_call),
        PExpr::Slice(n) => {
            n.lower.as_deref().is_some_and(expr_contains_call)
                || n.upper.as_deref().is_some_and(expr_contains_call)
                || n.step.as_deref().is_some_and(expr_contains_call)
        }
        // Name / Constant have no descendants.
        _ => false,
    }
}

fn comps_contain_call(gens: &[Comprehension]) -> bool {
    gens.iter().any(|g| {
        expr_contains_call(&g.target)
            || expr_contains_call(&g.iter)
            || g.ifs.iter().any(expr_contains_call)
    })
}

fn arguments_contain_call(args: &Arguments) -> bool {
    let ann = |a: &rustpython_parser::ast::Arg| a.annotation.as_deref().is_some_and(expr_contains_call);
    args.posonlyargs.iter().chain(args.args.iter()).chain(args.kwonlyargs.iter()).any(|a| {
        ann(&a.def) || a.default.as_deref().is_some_and(expr_contains_call)
    }) || args.vararg.as_deref().is_some_and(ann)
        || args.kwarg.as_deref().is_some_and(ann)
}

// -- CPython-faithful `ast.unparse` (subset) --------------------------------
//
// CPython's `ast._Unparser` precedence levels (Lib/_ast_unparse.py), as plain
// ints. A node is parenthesised when the precedence its parent *set* for it
// exceeds the node's own operator precedence.
const PR_NAMED_EXPR: i32 = 1;
const PR_TUPLE: i32 = 2;
const PR_TEST: i32 = 4;
const PR_OR: i32 = 5;
const PR_AND: i32 = 6;
const PR_NOT: i32 = 7;
const PR_CMP: i32 = 8;
const PR_EXPR: i32 = 9; // BOR
const PR_BXOR: i32 = 10;
const PR_BAND: i32 = 11;
const PR_SHIFT: i32 = 12;
const PR_ARITH: i32 = 13;
const PR_TERM: i32 = 14;
const PR_FACTOR: i32 = 15;
const PR_POWER: i32 = 16;
const PR_ATOM: i32 = 18;

fn pr_next(p: i32) -> i32 {
    if p >= PR_ATOM {
        PR_ATOM
    } else {
        p + 1
    }
}

/// `ast.unparse(expr)` for the Expr subset that appears in Python type
/// annotations and decorators, byte-faithful to CPython's `_Unparser`
/// (verified against the oracle). Scalar `Constant` repr and the rare exotic
/// nodes (f-strings, lambdas, comprehensions, await/yield) are delegated to
/// `rustpython-unparser`, whose output matches CPython for those leaves.
fn py_unparse(e: &PExpr) -> String {
    let mut out = String::new();
    emit_expr(e, PR_TEST, &mut out);
    out
}

fn delegate_unparse(e: &PExpr, out: &mut String) {
    let mut u = rustpython_unparser::Unparser::new();
    u.unparse_expr(e);
    out.push_str(&u.source);
}

fn is_int_constant(e: &PExpr) -> bool {
    matches!(e, PExpr::Constant(c) if matches!(c.value, PConstant::Int(_) | PConstant::Bool(_)))
}

/// `items_view`: comma-separated, with a trailing comma for a 1-tuple.
fn items_view(elts: &[PExpr], out: &mut String) {
    if elts.len() == 1 {
        emit_expr(&elts[0], PR_TEST, out);
        out.push(',');
    } else {
        for (i, e) in elts.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            emit_expr(e, PR_TEST, out);
        }
    }
}

/// Plain `, `-separated traversal (`interleave`).
fn interleave(elts: &[PExpr], out: &mut String) {
    for (i, e) in elts.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        emit_expr(e, PR_TEST, out);
    }
}

fn emit_expr(e: &PExpr, ctx: i32, out: &mut String) {
    match e {
        PExpr::Name(n) => out.push_str(n.id.as_str()),
        PExpr::Attribute(a) => {
            emit_expr(&a.value, PR_ATOM, out);
            // `3 .attr` — an int-literal receiver needs a separating space.
            if is_int_constant(&a.value) {
                out.push(' ');
            }
            out.push('.');
            out.push_str(a.attr.as_str());
        }
        PExpr::Subscript(s) => {
            emit_expr(&s.value, PR_ATOM, out);
            out.push('[');
            match &*s.slice {
                PExpr::Tuple(t) if !t.elts.is_empty() => items_view(&t.elts, out),
                other => emit_expr(other, PR_TEST, out),
            }
            out.push(']');
        }
        PExpr::Call(c) => {
            emit_expr(&c.func, PR_ATOM, out);
            out.push('(');
            let mut comma = false;
            for a in &c.args {
                if comma {
                    out.push_str(", ");
                } else {
                    comma = true;
                }
                emit_expr(a, PR_TEST, out);
            }
            for kw in &c.keywords {
                if comma {
                    out.push_str(", ");
                } else {
                    comma = true;
                }
                match &kw.arg {
                    None => out.push_str("**"),
                    Some(name) => {
                        out.push_str(name.as_str());
                        out.push('=');
                    }
                }
                emit_expr(&kw.value, PR_TEST, out);
            }
            out.push(')');
        }
        PExpr::Tuple(t) => {
            let parens = t.elts.is_empty() || ctx > PR_TUPLE;
            if parens {
                out.push('(');
            }
            items_view(&t.elts, out);
            if parens {
                out.push(')');
            }
        }
        PExpr::List(l) => {
            out.push('[');
            interleave(&l.elts, out);
            out.push(']');
        }
        PExpr::Set(s) => {
            if s.elts.is_empty() {
                out.push_str("{*()}");
            } else {
                out.push('{');
                interleave(&s.elts, out);
                out.push('}');
            }
        }
        PExpr::Dict(d) => {
            out.push('{');
            let mut first = true;
            for (k, v) in d.keys.iter().zip(d.values.iter()) {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                match k {
                    Some(key) => {
                        emit_expr(key, PR_TEST, out);
                        out.push_str(": ");
                        emit_expr(v, PR_TEST, out);
                    }
                    None => {
                        out.push_str("**");
                        emit_expr(v, PR_EXPR, out);
                    }
                }
            }
            out.push('}');
        }
        PExpr::Starred(s) => {
            out.push('*');
            emit_expr(&s.value, PR_EXPR, out);
        }
        PExpr::Slice(s) => {
            if let Some(l) = &s.lower {
                emit_expr(l, PR_TEST, out);
            }
            out.push(':');
            if let Some(u) = &s.upper {
                emit_expr(u, PR_TEST, out);
            }
            if let Some(st) = &s.step {
                out.push(':');
                emit_expr(st, PR_TEST, out);
            }
        }
        PExpr::BinOp(b) => emit_binop(b, ctx, out),
        PExpr::UnaryOp(u) => emit_unaryop(u, ctx, out),
        PExpr::BoolOp(b) => emit_boolop(b, ctx, out),
        PExpr::Compare(c) => emit_compare(c, ctx, out),
        PExpr::IfExp(n) => {
            let parens = ctx > PR_TEST;
            if parens {
                out.push('(');
            }
            emit_expr(&n.body, pr_next(PR_TEST), out);
            out.push_str(" if ");
            emit_expr(&n.test, pr_next(PR_TEST), out);
            out.push_str(" else ");
            emit_expr(&n.orelse, PR_TEST, out);
            if parens {
                out.push(')');
            }
        }
        PExpr::NamedExpr(n) => {
            let parens = ctx > PR_NAMED_EXPR;
            if parens {
                out.push('(');
            }
            emit_expr(&n.target, PR_ATOM, out);
            out.push_str(" := ");
            emit_expr(&n.value, PR_ATOM, out);
            if parens {
                out.push(')');
            }
        }
        // Scalar Constant repr + exotic nodes (f-strings, lambda, comprehensions,
        // await/yield) — delegated to rustpython-unparser.
        _ => delegate_unparse(e, out),
    }
}

fn binop_info(op: &Operator) -> (&'static str, i32) {
    match op {
        Operator::Add => ("+", PR_ARITH),
        Operator::Sub => ("-", PR_ARITH),
        Operator::Mult => ("*", PR_TERM),
        Operator::MatMult => ("@", PR_TERM),
        Operator::Div => ("/", PR_TERM),
        Operator::Mod => ("%", PR_TERM),
        Operator::LShift => ("<<", PR_SHIFT),
        Operator::RShift => (">>", PR_SHIFT),
        Operator::BitOr => ("|", PR_EXPR),
        Operator::BitXor => ("^", PR_BXOR),
        Operator::BitAnd => ("&", PR_BAND),
        Operator::FloorDiv => ("//", PR_TERM),
        Operator::Pow => ("**", PR_POWER),
    }
}

fn emit_binop(b: &ExprBinOp, ctx: i32, out: &mut String) {
    let (op, prec) = binop_info(&b.op);
    let parens = ctx > prec;
    if parens {
        out.push('(');
    }
    // `**` is right-associative; everything else is left-associative.
    let rassoc = matches!(b.op, Operator::Pow);
    let (lp, rp) = if rassoc {
        (pr_next(prec), prec)
    } else {
        (prec, pr_next(prec))
    };
    emit_expr(&b.left, lp, out);
    out.push(' ');
    out.push_str(op);
    out.push(' ');
    emit_expr(&b.right, rp, out);
    if parens {
        out.push(')');
    }
}

fn emit_unaryop(u: &ExprUnaryOp, ctx: i32, out: &mut String) {
    let (op, prec) = match u.op {
        UnaryOp::Invert => ("~", PR_FACTOR),
        UnaryOp::Not => ("not", PR_NOT),
        UnaryOp::UAdd => ("+", PR_FACTOR),
        UnaryOp::USub => ("-", PR_FACTOR),
    };
    let parens = ctx > prec;
    if parens {
        out.push('(');
    }
    out.push_str(op);
    // Factor prefixes (+, -, ~) bind tight: no separating space.
    if prec != PR_FACTOR {
        out.push(' ');
    }
    emit_expr(&u.operand, prec, out);
    if parens {
        out.push(')');
    }
}

fn emit_boolop(b: &ExprBoolOp, ctx: i32, out: &mut String) {
    let (op, prec) = match b.op {
        BoolOp::And => ("and", PR_AND),
        BoolOp::Or => ("or", PR_OR),
    };
    let parens = ctx > prec;
    if parens {
        out.push('(');
    }
    let mut lvl = prec;
    for (i, v) in b.values.iter().enumerate() {
        if i > 0 {
            out.push(' ');
            out.push_str(op);
            out.push(' ');
        }
        lvl = pr_next(lvl);
        emit_expr(v, lvl, out);
    }
    if parens {
        out.push(')');
    }
}

fn cmpop_str(op: &CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "==",
        CmpOp::NotEq => "!=",
        CmpOp::Lt => "<",
        CmpOp::LtE => "<=",
        CmpOp::Gt => ">",
        CmpOp::GtE => ">=",
        CmpOp::Is => "is",
        CmpOp::IsNot => "is not",
        CmpOp::In => "in",
        CmpOp::NotIn => "not in",
    }
}

fn emit_compare(c: &ExprCompare, ctx: i32, out: &mut String) {
    let parens = ctx > PR_CMP;
    if parens {
        out.push('(');
    }
    emit_expr(&c.left, pr_next(PR_CMP), out);
    for (op, comp) in c.ops.iter().zip(c.comparators.iter()) {
        out.push(' ');
        out.push_str(cmpop_str(op));
        out.push(' ');
        emit_expr(comp, pr_next(PR_CMP), out);
    }
    if parens {
        out.push(')');
    }
}

fn global_names(node: Node, language: &str, src: &[u8]) -> Vec<String> {
    match language {
        "python" => global_names_python(node, src),
        "go" => global_names_go(node, src),
        "javascript" | "typescript" | "tsx" => global_names_js(node, src),
        "c" | "cpp" => global_names_c(node, src),
        "java" => global_names_java(node, src),
        _ => Vec::new(),
    }
}

/// Java field name — the first `variable_declarator`'s identifier
/// (`_global_name` Java branch).
fn global_names_java(node: Node, src: &[u8]) -> Vec<String> {
    for child in children(node) {
        if child.kind() == "variable_declarator" {
            for sub in children(child) {
                if sub.kind() == "identifier" {
                    return vec![text(sub, src).to_string()];
                }
            }
        }
    }
    Vec::new()
}

/// C/C++ global name. Function prototypes (a direct `function_declarator`
/// child) are skipped; otherwise descend the declarator wrappers to the
/// declared identifier (`_global_name` C branch + `_c_declarator_name`).
fn global_names_c(node: Node, src: &[u8]) -> Vec<String> {
    if children(node).iter().any(|c| c.kind() == "function_declarator") {
        return Vec::new();
    }
    match c_declarator_name(node, src, 0) {
        Some(n) => vec![n],
        None => Vec::new(),
    }
}

fn c_declarator_name(node: Node, src: &[u8], depth: u32) -> Option<String> {
    if depth > 6 {
        return None;
    }
    if node.kind() == "identifier" {
        return Some(text(node, src).to_string());
    }
    for child in children(node) {
        match child.kind() {
            "identifier" => return Some(text(child, src).to_string()),
            "init_declarator" => {
                // Follow only the declarator side, never the RHS init value.
                let decl = child
                    .child_by_field_name("declarator")
                    .or_else(|| children(child).into_iter().next());
                if let Some(d) = decl {
                    if let Some(name) = c_declarator_name(d, src, depth + 1) {
                        return Some(name);
                    }
                }
            }
            "array_declarator" | "pointer_declarator" | "parenthesized_declarator"
            | "function_declarator" => {
                if let Some(name) = c_declarator_name(child, src, depth + 1) {
                    return Some(name);
                }
            }
            _ => {}
        }
    }
    None
}

/// JS/TS global name — the first `variable_declarator`'s identifier (the Python
/// `_global_name` JS branch yields a single name per declaration node).
fn global_names_js(node: Node, src: &[u8]) -> Vec<String> {
    for child in children(node) {
        if child.kind() == "variable_declarator" {
            for sub in children(child) {
                if matches!(sub.kind(), "identifier" | "name") {
                    return vec![text(sub, src).to_string()];
                }
            }
        }
    }
    Vec::new()
}

/// Go `var_spec`/`const_spec` identifier names. A `var ( … )` block nests its
/// specs in a `var_spec_list` (not a direct child), so those names are dropped
/// — faithful to the Python `_global_names` Go branch.
fn global_names_go(node: Node, src: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for child in children(node) {
        if matches!(child.kind(), "var_spec" | "const_spec") {
            for sub in children(child) {
                if sub.kind() == "identifier" {
                    out.push(text(sub, src).to_string());
                }
            }
        }
    }
    out
}

fn global_names_python(node: Node, src: &[u8]) -> Vec<String> {
    // Unwrap expression_statement → assignment.
    let target = if node.kind() == "expression_statement" {
        children(node).into_iter().find(|c| c.kind() == "assignment")
    } else {
        Some(node)
    };
    let mut out: Vec<String> = Vec::new();
    let Some(t) = target else { return out };
    if t.kind() != "assignment" {
        return out;
    }
    // Walk the NESTED chained-assignment shape `A = B = 1`, yielding the
    // leading identifiers at each level that pass the UPPER/TitleCase filter.
    let mut current = Some(t);
    while let Some(cur) = current {
        if cur.kind() != "assignment" {
            break;
        }
        let mut next_assignment = None;
        for c in children(cur) {
            if c.kind() == "identifier" {
                let nm = text(c, src);
                if !nm.is_empty() && (py_isupper(nm) || (first_isupper(nm) && !py_islower(nm))) {
                    out.push(nm.to_string());
                }
            } else if c.kind() == "assignment" {
                next_assignment = Some(c);
                break;
            }
        }
        current = next_assignment;
    }
    out
}

/// `str.isupper()`: at least one cased char, no lowercase.
fn py_isupper(s: &str) -> bool {
    let mut has_cased = false;
    for c in s.chars() {
        if c.is_lowercase() {
            return false;
        }
        if c.is_uppercase() {
            has_cased = true;
        }
    }
    has_cased
}

/// `str.islower()`: at least one cased char, no uppercase.
fn py_islower(s: &str) -> bool {
    let mut has_cased = false;
    for c in s.chars() {
        if c.is_uppercase() {
            return false;
        }
        if c.is_lowercase() {
            has_cased = true;
        }
    }
    has_cased
}

fn first_isupper(s: &str) -> bool {
    s.chars().next().is_some_and(char::is_uppercase)
}

// ---------------------------------------------------------------------------
// SLOC counting (tree-sitter comment detection) — `count_sloc`.
// ---------------------------------------------------------------------------

const COMMENT_KINDS: &[&str] = &["comment", "line_comment", "block_comment"];

/// Count source lines of code (non-blank, non-comment) using tree-sitter
/// comment detection. Faithful to `count_sloc` for the wired grammars; an
/// unparseable/unwired language returns total - blank (no comment detection).
pub fn count_sloc(language: &str, content: &str) -> i64 {
    let lines = crate::extractors::splitlines(content);
    let total = lines.len() as i64;
    let blank = lines.iter().filter(|l| l.trim().is_empty()).count() as i64;
    let comment_lines = match mantishack_ts::parse(language, content) {
        Some(tree) => count_comment_lines_ts(tree.root_node(), content.as_bytes()),
        None => 0,
    };
    (total - blank - comment_lines).max(0)
}

fn count_comment_lines_ts(root: Node, src: &[u8]) -> i64 {
    use std::collections::HashSet;
    let mut code_lines: HashSet<usize> = HashSet::new();
    collect_code_lines(root, src, &mut code_lines);
    let mut comment_lines: HashSet<usize> = HashSet::new();
    collect_comment_lines(root, &code_lines, &mut comment_lines);
    comment_lines.len() as i64
}

fn collect_code_lines(node: Node, src: &[u8], code_lines: &mut std::collections::HashSet<usize>) {
    let kids = children(node);
    // Leaf node that isn't a comment, with non-whitespace text → code.
    if kids.is_empty() && !COMMENT_KINDS.contains(&node.kind()) && !text(node, src).trim().is_empty() {
        for line in node.start_position().row..=node.end_position().row {
            code_lines.insert(line);
        }
    }
    for child in kids {
        collect_code_lines(child, src, code_lines);
    }
}

fn collect_comment_lines(
    node: Node,
    code_lines: &std::collections::HashSet<usize>,
    comment_lines: &mut std::collections::HashSet<usize>,
) {
    if COMMENT_KINDS.contains(&node.kind()) {
        for line in node.start_position().row..=node.end_position().row {
            if !code_lines.contains(&line) {
                comment_lines.insert(line);
            }
        }
    }
    for child in children(node) {
        collect_comment_lines(child, code_lines, comment_lines);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PythonExtractor (`python_ast_extract`) oracle-differential tests --
    // Expected values transcribed from the real `PythonExtractor().extract(...)`
    // (`core.inventory.extractors`). Each item is `FunctionInfo`/`CodeItem`
    // `.to_dict()`.
    use serde_json::{json, Value};

    fn pyx(src: &str) -> Value {
        Value::Array(python_ast_extract(src).iter().map(InventoryItem::to_json).collect())
    }

    fn items_json(src: &str) -> Value {
        Value::Array(extract_items("python", src).iter().map(InventoryItem::to_json).collect())
    }

    #[allow(clippy::too_many_arguments)]
    fn func(
        name: &str,
        ls: i64,
        le: Value,
        sig: &str,
        class_name: Value,
        attributes: Value,
        return_type: Value,
        parameters: Value,
    ) -> Value {
        json!({
            "name": name, "kind": "function", "line_start": ls, "line_end": le,
            "signature": sig, "checked_by": [],
            "metadata": {
                "class_name": class_name, "visibility": null, "attributes": attributes,
                "return_type": return_type, "parameters": parameters, "class_attributes": [],
            },
        })
    }

    #[test]
    fn pyx_annotations_and_unparse() {
        // ast.unparse on annotations: Optional[str], Dict[str, int] (no inner
        // parens), `int | None`, forward-ref return; default-valued params keep
        // their name only (no default text in signature).
        let src = "def f(a: Optional[str], b: Dict[str, int], c: int | None = 3, d=5) -> 'Ret':\n    return None\n";
        assert_eq!(
            pyx(src),
            json!([func(
                "f", 1, json!(2),
                "def f(a: Optional[str], b: Dict[str, int], c: int | None, d) -> 'Ret'",
                json!(null), json!([]), json!("'Ret'"),
                json!([["a", "Optional[str]"], ["b", "Dict[str, int]"], ["c", "int | None"], ["d", null]]),
            )])
        );
    }

    #[test]
    fn pyx_async_and_return_type() {
        let src = "async def g(x: int) -> None:\n    await h()\n";
        assert_eq!(
            pyx(src),
            json!([func("g", 1, json!(2), "async def g(x: int) -> None", json!(null), json!([]), json!("None"), json!([["x", "int"]]))])
        );
    }

    #[test]
    fn pyx_method_nested_keeps_class_name() {
        // A function nested inside a method keeps the enclosing class_name.
        let src = "class C:\n    def m(self, n: int) -> str:\n        def inner(z):\n            return z\n        return inner(n)\n";
        assert_eq!(
            pyx(src),
            json!([
                func("m", 2, json!(5), "def m(self, n: int) -> str", json!("C"), json!([]), json!("str"), json!([["self", null], ["n", "int"]])),
                func("inner", 3, json!(4), "def inner(z)", json!("C"), json!([]), json!(null), json!([["z", null]])),
            ])
        );
    }

    #[test]
    fn pyx_nested_in_if_branches() {
        let src = "if FLAG:\n    def guarded(a):\n        pass\nelse:\n    def other():\n        pass\n";
        assert_eq!(
            pyx(src),
            json!([
                func("guarded", 2, json!(3), "def guarded(a)", json!(null), json!([]), json!(null), json!([["a", null]])),
                func("other", 5, json!(6), "def other()", json!(null), json!([]), json!(null), json!([])),
            ])
        );
    }

    #[test]
    fn pyx_decorators_unparse_full_expression() {
        let src = "import functools\n@app.route('/x', methods=['GET'])\n@functools.lru_cache(maxsize=None)\ndef handler(req):\n    pass\n";
        assert_eq!(
            pyx(src),
            json!([func(
                "handler", 4, json!(5), "def handler(req)", json!(null),
                json!(["app.route('/x', methods=['GET'])", "functools.lru_cache(maxsize=None)"]),
                json!(null), json!([["req", null]]),
            )])
        );
    }

    #[test]
    fn pyx_generics_unparse() {
        let src = "def t(cb: Callable[[int, str], bool], m: Dict[str, List[int]]) -> Tuple[int, ...]:\n    pass\n";
        assert_eq!(
            pyx(src),
            json!([func(
                "t", 1, json!(2),
                "def t(cb: Callable[[int, str], bool], m: Dict[str, List[int]]) -> Tuple[int, ...]",
                json!(null), json!([]), json!("Tuple[int, ...]"),
                json!([["cb", "Callable[[int, str], bool]"], ["m", "Dict[str, List[int]]"]]),
            )])
        );
    }

    #[test]
    fn pyx_posonly_and_kwonly_excluded() {
        // node.args.args = regular positional only: `c` (a,b are posonly; d,e
        // kwonly; *args/**kw excluded).
        let src = "def s(a, b, /, c, *args, d, e=1, **kw):\n    pass\n";
        assert_eq!(
            pyx(src),
            json!([func("s", 1, json!(2), "def s(c)", json!(null), json!([]), json!(null), json!([["c", null]]))])
        );
    }

    #[test]
    fn pyx_top_level_items_only_expr_with_call() {
        // os.system(...) and print(...) are top_level; `x = compute()` is an
        // assignment (a global), `LABEL = 'k'` too — neither is top_level.
        let src = "import os\nos.system('id')\nprint('hi')\nx = compute()\nLABEL = 'k'\n";
        assert_eq!(
            pyx(src),
            json!([
                {"name": "top_level:2", "kind": "top_level", "line_start": 2, "line_end": 2, "checked_by": []},
                {"name": "top_level:3", "kind": "top_level", "line_start": 3, "line_end": 3, "checked_by": []},
            ])
        );
    }

    #[test]
    fn pyx_syntax_error_regex_fallback() {
        // Unparseable -> regex fallback: `def NAME(` lines, no metadata/signature.
        let src = "def broken(:\n    pass\ndef ok(a):\n    pass\n";
        assert_eq!(
            pyx(src),
            json!([
                {"name": "broken", "kind": "function", "line_start": 1, "line_end": null, "signature": null, "checked_by": []},
                {"name": "ok", "kind": "function", "line_start": 3, "line_end": null, "signature": null, "checked_by": []},
            ])
        );
    }

    #[test]
    fn pyx_class_decorated_methods() {
        let src = "class S:\n    @staticmethod\n    def util(x: 'Foo') -> 'Bar':\n        pass\n    @property\n    def val(self):\n        return 1\n";
        assert_eq!(
            pyx(src),
            json!([
                func("util", 3, json!(4), "def util(x: 'Foo') -> 'Bar'", json!("S"), json!(["staticmethod"]), json!("'Bar'"), json!([["x", "'Foo'"]])),
                func("val", 6, json!(7), "def val(self)", json!("S"), json!(["property"]), json!(null), json!([["self", null]])),
            ])
        );
    }

    #[test]
    fn pyx_nested_in_try_with_finally() {
        let src = "with open() as fh:\n    def w():\n        pass\ntry:\n    pass\nfinally:\n    def fin(a: int):\n        pass\n";
        assert_eq!(
            pyx(src),
            json!([
                func("w", 2, json!(3), "def w()", json!(null), json!([]), json!(null), json!([])),
                func("fin", 7, json!(8), "def fin(a: int)", json!(null), json!([]), json!(null), json!([["a", "int"]])),
            ])
        );
    }

    // ---- extract_items integration (Python fallback orchestration) ---------

    #[test]
    fn items_with_functions_uses_tree_sitter() {
        // Tree-sitter functions (signature has no `def` prefix / no self),
        // global MAX, and top_level os.system(...).
        let src = "import os\n\nMAX = 10\n\ndef a(x: int) -> int:\n    return x\n\nos.system('id')\n\nclass C:\n    def m(self):\n        pass\n";
        assert_eq!(
            items_json(src),
            json!([
                {"name": "a", "kind": "function", "line_start": 5, "line_end": 6, "signature": "a(x: int) -> int", "checked_by": [],
                 "metadata": {"class_name": null, "visibility": null, "attributes": [], "return_type": "int", "parameters": [["x", "int"]], "class_attributes": []}},
                {"name": "m", "kind": "function", "line_start": 11, "line_end": 12, "signature": "m()", "checked_by": [],
                 "metadata": {"class_name": "C", "visibility": null, "attributes": [], "return_type": null, "parameters": [], "class_attributes": []}},
                {"name": "MAX", "kind": "global", "line_start": 3, "line_end": 3, "checked_by": []},
                {"name": "top_level:8", "kind": "top_level", "line_start": 8, "line_end": 8, "checked_by": []},
            ])
        );
    }

    #[test]
    fn items_zero_functions_falls_back_to_ast() {
        // No `def` -> tree-sitter yields no functions -> AST fallback re-derives
        // top_level (keeps tree-sitter globals CONST/MyConfig).
        let src = "import os\n\nCONST = 1\nMyConfig = object()\n\nos.system('id')\nprint('hi')\nlogger = setup()\n";
        assert_eq!(
            items_json(src),
            json!([
                {"name": "CONST", "kind": "global", "line_start": 3, "line_end": 3, "checked_by": []},
                {"name": "MyConfig", "kind": "global", "line_start": 4, "line_end": 4, "checked_by": []},
                {"name": "top_level:6", "kind": "top_level", "line_start": 6, "line_end": 6, "checked_by": []},
                {"name": "top_level:7", "kind": "top_level", "line_start": 7, "line_end": 7, "checked_by": []},
            ])
        );
    }

    #[test]
    fn items_lenient_parse_no_fallback() {
        // `def broken(:` parses under tree-sitter (yields `broken`), so the AST
        // fallback (which would regex-only) does NOT trigger.
        let src = "def broken(:\n    pass\nVALUE = 3\n";
        assert_eq!(
            items_json(src),
            json!([
                {"name": "broken", "kind": "function", "line_start": 1, "line_end": 2, "signature": "broken()", "checked_by": [],
                 "metadata": {"class_name": null, "visibility": null, "attributes": [], "return_type": null, "parameters": [], "class_attributes": []}},
                {"name": "VALUE", "kind": "global", "line_start": 3, "line_end": 3, "checked_by": []},
            ])
        );
    }

    #[test]
    fn py_unparse_subscript_tuple_omits_parens() {
        // Direct unparser checks for the CPython-faithful behaviours that the
        // off-the-shelf rustpython unparser gets wrong (subscript tuple parens).
        use rustpython_parser::ast::Expr;
        let cases = [
            ("Dict[str, int]", "Dict[str, int]"),
            ("Tuple[int, ...]", "Tuple[int, ...]"),
            ("Callable[[int, str], bool]", "Callable[[int, str], bool]"),
            ("Optional[Dict[str, int]]", "Optional[Dict[str, int]]"),
            ("Union[int, str, None]", "Union[int, str, None]"),
            ("int | None", "int | None"),
            ("Tuple[()]", "Tuple[()]"),
            ("Callable[..., int]", "Callable[..., int]"),
            ("a.b.c", "a.b.c"),
            ("dataclass(frozen=True)", "dataclass(frozen=True)"),
        ];
        for (src, want) in cases {
            let e = Expr::parse(src, "<u>").unwrap();
            assert_eq!(py_unparse(&e), want, "py_unparse({src})");
        }
    }

    fn names(fns: &[FunctionInfo]) -> Vec<&str> {
        fns.iter().map(|f| f.name.as_str()).collect()
    }

    #[test]
    fn decorated_function_and_plain_param_dropped() {
        let src = "import os\n\n@decorator\ndef foo(a, b=2):\n    return a + b\n";
        let fns = extract_python_functions(src);
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        assert_eq!(f.name, "foo");
        assert_eq!((f.line_start, f.line_end), (4, Some(5)));
        // Plain `a` dropped; `b=2` keeps name only → signature foo(b).
        assert_eq!(f.signature.as_deref(), Some("foo(b)"));
        let m = f.metadata.as_ref().unwrap();
        assert_eq!(m.attributes, vec!["decorator"]);
        assert_eq!(m.parameters, vec![("b".to_string(), None)]);
        assert_eq!(m.class_name, None);
    }

    #[test]
    fn method_carries_class_name_and_self_excluded() {
        let src = "class C:\n    def method(self, x):\n        return x\n";
        let fns = extract_python_functions(src);
        assert_eq!(names(&fns), vec!["method"]);
        let m = fns[0].metadata.as_ref().unwrap();
        assert_eq!(m.class_name.as_deref(), Some("C"));
        assert_eq!(fns[0].signature.as_deref(), Some("method()"));
        assert!(m.parameters.is_empty());
    }

    #[test]
    fn typed_params_and_return_type() {
        let src = "def f(x: int, y: str = \"a\") -> bool:\n    return True\n";
        let fns = extract_python_functions(src);
        let f = &fns[0];
        assert_eq!(f.signature.as_deref(), Some("f(x: int, y: str) -> bool"));
        let m = f.metadata.as_ref().unwrap();
        assert_eq!(
            m.parameters,
            vec![("x".to_string(), Some("int".to_string())), ("y".to_string(), Some("str".to_string()))]
        );
        assert_eq!(m.return_type.as_deref(), Some("bool"));
    }

    #[test]
    fn nested_function_and_class() {
        let src = "def outer():\n    def inner():\n        pass\n    return inner\n";
        let fns = extract_python_functions(src);
        // Both outer and inner are extracted (walk recurses).
        assert!(names(&fns).contains(&"outer"));
        assert!(names(&fns).contains(&"inner"));
    }

    #[test]
    fn no_functions() {
        assert!(extract_python_functions("x = 1\ny = 2\n").is_empty());
    }

    fn item_names(items: &[CodeItem]) -> Vec<&str> {
        items.iter().map(|c| c.name.as_str()).collect()
    }

    #[test]
    fn globals_only_upper_or_titlecase() {
        let src = "GLOBAL = 1\nx = 2\nConfig = {}\n_PRIVATE = 3\nmyVar = 4\n";
        let g = extract_python_globals(src);
        assert_eq!(item_names(&g), vec!["GLOBAL", "Config", "_PRIVATE"]);
    }

    #[test]
    fn globals_chained_assignment() {
        let g = extract_python_globals("A = B = C = 1\n");
        assert_eq!(item_names(&g), vec!["A", "B", "C"]);
    }

    #[test]
    fn top_level_call_not_assignment() {
        let src = "import os\nos.system(\"x\")\nY = compute()\nprint(1)\n";
        let t = extract_python_top_level(src);
        // os.system(...) on line 2 and print(1) on line 4; the Y = compute()
        // assignment is a global, not top_level.
        assert_eq!(item_names(&t), vec!["top_level:2", "top_level:4"]);
    }

    // --- JavaScript ------------------------------------------------------

    #[test]
    fn js_class_method_public_and_export() {
        let src = "class C {\n  method(a) { return a; }\n}\nexport function pub(x) {}\n";
        let fns = extract_javascript_functions(src);
        assert_eq!(names(&fns), vec!["method", "pub"]);
        let m0 = fns[0].metadata.as_ref().unwrap();
        assert_eq!(m0.class_name.as_deref(), Some("C"));
        assert_eq!(m0.visibility.as_deref(), Some("public"));
        let m1 = fns[1].metadata.as_ref().unwrap();
        assert_eq!(m1.visibility.as_deref(), Some("exported"));
    }

    #[test]
    fn js_arrow_in_declarator_function_expression_skipped() {
        let src = "const f = (x) => x * 2;\nconst g = function(y) { return y; };\n";
        let fns = extract_javascript_functions(src);
        // Arrow `f` captured; `function(y)` is a function_expression node, which
        // the find_child(arrow_function|function) miss drops — matching Python.
        assert_eq!(names(&fns), vec!["f"]);
        assert_eq!(fns[0].signature.as_deref(), Some("f = (x) => x * 2"));
    }

    // --- C ---------------------------------------------------------------

    #[test]
    fn c_typed_params_and_return() {
        let fns = extract_c_functions("int add(int a, int b) {\n    return a + b;\n}\n");
        let f = &fns[0];
        assert_eq!(f.name, "add");
        assert_eq!(f.signature.as_deref(), Some("add(a: int, b: int) -> int"));
        let m = f.metadata.as_ref().unwrap();
        assert_eq!(m.return_type.as_deref(), Some("int"));
        assert_eq!(
            m.parameters,
            vec![("a".to_string(), Some("int".to_string())), ("b".to_string(), Some("int".to_string()))]
        );
    }

    #[test]
    fn c_pointer_return_drops_params_and_return_type() {
        // function_declarator nested in pointer_declarator → no params/return.
        let fns = extract_c_functions("static char *get_name(const char *path) {\n    return 0;\n}\n");
        let f = &fns[0];
        assert_eq!(f.name, "get_name");
        assert_eq!(f.signature.as_deref(), Some("get_name()"));
        let m = f.metadata.as_ref().unwrap();
        assert_eq!(m.visibility.as_deref(), Some("static"));
        assert!(m.parameters.is_empty());
        assert_eq!(m.return_type, None);
    }

    #[test]
    fn c_double_pointer_param_type() {
        let fns = extract_c_functions("int main(int argc, char **argv) { return 0; }\n");
        let m = fns[0].metadata.as_ref().unwrap();
        assert_eq!(
            m.parameters,
            vec![("argc".to_string(), Some("int".to_string())), ("argv".to_string(), Some("char*".to_string()))]
        );
    }

    // --- Go --------------------------------------------------------------

    #[test]
    fn go_exported_capitalization_and_return() {
        let fns = extract_go_functions("func Add(a int, b int) int { return a + b }\n");
        let f = &fns[0];
        assert_eq!(f.signature.as_deref(), Some("Add(a: int, b: int) -> int"));
        assert_eq!(f.metadata.as_ref().unwrap().visibility.as_deref(), Some("exported"));
    }

    #[test]
    fn go_method_receiver_is_class_name() {
        let src = "func (t *T) Method(n int) error {\n    return nil\n}\n";
        let fns = extract_go_functions(src);
        let m = fns[0].metadata.as_ref().unwrap();
        assert_eq!(fns[0].name, "Method");
        assert_eq!(m.class_name.as_deref(), Some("T"));
        // Receiver `t *T` is included as the first parameter.
        assert_eq!(m.parameters[0], ("t".to_string(), Some("*T".to_string())));
    }

    #[test]
    fn go_block_var_globals_dropped() {
        // Single var/const captured; `var ( … )` block specs nest in
        // var_spec_list and are dropped — matching Python.
        let g = extract_go_globals("var Global = 1\nconst Max = 9\nvar (\n  a int\n)\n");
        assert_eq!(item_names(&g), vec!["Global", "Max"]);
    }

    // --- Java ------------------------------------------------------------

    #[test]
    fn java_method_visibility_and_class_name() {
        let src = "public class Foo {\n    public int add(int a, int b) { return a + b; }\n    private void helper() {}\n}\n";
        let fns = extract_java_functions(src);
        assert_eq!(names(&fns), vec!["add", "helper"]);
        let m0 = fns[0].metadata.as_ref().unwrap();
        assert_eq!(m0.class_name.as_deref(), Some("Foo"));
        assert_eq!(m0.visibility.as_deref(), Some("public"));
        // Java `int` is integral_type (not in the type set) → params lose types.
        assert_eq!(fns[0].signature.as_deref(), Some("add(a, b)"));
        assert_eq!(fns[1].metadata.as_ref().unwrap().visibility.as_deref(), Some("private"));
    }

    #[test]
    fn java_annotations_and_stereotype() {
        let src = "@Service\npublic class Svc {\n    @GetMapping\n    public String handle(Request req) { return \"x\"; }\n}\n";
        let m = extract_java_functions(src)[0].metadata.clone().unwrap();
        assert_eq!(m.attributes, vec!["GetMapping"]); // method annotation
        assert_eq!(m.class_attributes, vec!["Service"]); // class stereotype
        assert_eq!(m.parameters, vec![("req".to_string(), Some("Request".to_string()))]);
    }

    #[test]
    fn extract_items_combines_functions_globals_top_level_macros() {
        let src = "#define MAX 100\nint g = 5;\nint add(int a) { return a; }\n";
        let items = extract_items("c", src);
        let kinds: Vec<&str> = items.iter().map(|i| i.kind()).collect();
        // function, then global, then macro (C order).
        assert_eq!(kinds, vec!["function", "global", "macro"]);
        match &items[0] {
            InventoryItem::Function(f) => assert_eq!(f.name, "add"),
            _ => panic!("expected function first"),
        }
    }

    #[test]
    fn count_sloc_excludes_blank_and_comments() {
        // 6 lines: comment, fn header, block-comment (2), return+trailing, close.
        let src = "// a comment\nint add(int a) {\n    /* block\n       comment */\n    return a; // trailing\n}\n";
        // Code lines: 2 (header), 5 (return), 6 (close) = 3.
        assert_eq!(count_sloc("c", src), 3);
    }

    #[test]
    fn count_sloc_python_docstring_counts_as_code() {
        let src = "def f():\n    \"\"\"doc\n    lines\n    \"\"\"\n    return 1\n";
        // A docstring is a `string` node (not a comment), so its lines count
        // as code — matching the oracle's tree-sitter behaviour. 5 non-blank
        // lines, 0 comments → 5.
        assert_eq!(count_sloc("python", src), 5);
    }

    #[test]
    fn java_base_type_and_fields() {
        let src = "class Repo extends JpaRepository<Owner, Integer> {\n    public Owner find(int id) { return null; }\n}\n";
        let m = extract_java_functions(src)[0].metadata.clone().unwrap();
        assert_eq!(m.class_attributes, vec!["JpaRepository"]); // base tail-name
        let g = extract_globals("java", "public class C {\n    static final int MAX = 1;\n    String name;\n}\n");
        assert_eq!(item_names(&g), vec!["MAX", "name"]);
    }
}
