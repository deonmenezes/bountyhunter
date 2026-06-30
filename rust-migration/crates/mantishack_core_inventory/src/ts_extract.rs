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
use tree_sitter::Node;

use crate::extractors::{CodeItem, KIND_FUNCTION, KIND_GLOBAL, KIND_TOP_LEVEL};

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
            // decorated_definition wrapper.
            let mut attrs = ts_decorators(child, src, language);
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
            // Java: `extends Foo` (superclass) / `implements Bar`
            // (super_interfaces) — record the base type tail-names so a
            // framework base (JpaRepository, Validator …) marks the class.
            "superclass" | "super_interfaces" | "extends_interfaces" => {
                java_base_names(child, src, &mut out);
            }
            _ => {}
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
    // (csharp modifiers branch: added with C#.)

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
/// top-level ++ macros, in that order. The Python no-function fallback (which
/// re-runs the `ast`/regex extractors for functions) is NOT applied — a
/// documented gap that only affects files with zero extracted functions.
pub fn extract_items(language: &str, content: &str) -> Vec<InventoryItem> {
    let mut items: Vec<InventoryItem> = Vec::new();
    for f in extract_functions(language, content) {
        items.push(InventoryItem::Function(f));
    }
    for g in extract_globals(language, content) {
        items.push(InventoryItem::Item(g));
    }
    for t in extract_top_level(language, content) {
        items.push(InventoryItem::Item(t));
    }
    if matches!(language, "c" | "cpp") {
        for m in crate::extractors::extract_macros(content) {
            items.push(InventoryItem::Item(m));
        }
    }
    items
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
