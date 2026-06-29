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
pub fn extract_functions(language: &str, content: &str) -> Vec<FunctionInfo> {
    let Some(tree) = mantishack_ts::parse(language, content) else {
        return Vec::new();
    };
    let src = content.as_bytes();
    let mut out: Vec<FunctionInfo> = Vec::new();
    walk(tree.root_node(), src, language, &mut out, None, &[]);
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
        _ => &[],
    }
}

/// Node types that represent classes per language (`_CLASS_TYPES`).
fn class_types(language: &str) -> &'static [&'static str] {
    match language {
        "python" => &["class_definition"],
        "javascript" => &["class_declaration"],
        "typescript" | "tsx" => &["class_declaration", "abstract_class_declaration"],
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
        if child.kind() == "modifiers" {
            for m in children(child) {
                if matches!(m.kind(), "marker_annotation" | "annotation") {
                    out.push(lstrip_at(text(m, src)));
                }
            }
        }
    }
    out
}

/// Extract visibility and (possibly updated) class_name. Python branch returns
/// `(None, class_name)`; JS sets member visibility for `method_definition` and
/// `exported` for an `export_statement` parent (`_extract_visibility`).
fn extract_visibility(
    node: Node,
    src: &[u8],
    language: &str,
    class_name: Option<&str>,
) -> (Option<String>, Option<String>) {
    let mut visibility = None;
    if node.kind() == "method_definition" {
        visibility = ts_member_visibility(node, src, language);
    }
    // (csharp / java modifiers / go branches: added with those languages.)

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

    if let Some(parent) = node.parent() {
        if parent.kind() == "export_statement" {
            visibility = Some("exported".to_string());
        }
    }
    (visibility, class_name.map(str::to_string))
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
    let (visibility, class_name) = extract_visibility(node, src, language, class_name);
    let _ = &mut attrs; // attrs is mutated by Java/C# branches (added later)
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

/// Module-scope executable statements (run at import) as `top_level` items —
/// a root-level `expression_statement` containing a call but not an assignment.
/// Faithful port of `_extract_top_level_ts` for Python.
pub fn extract_python_top_level(content: &str) -> Vec<CodeItem> {
    let Some(tree) = mantishack_ts::parse("python", content) else {
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
pub fn extract_python_globals(content: &str) -> Vec<CodeItem> {
    let Some(tree) = mantishack_ts::parse("python", content) else {
        return Vec::new();
    };
    let src = content.as_bytes();
    let root = tree.root_node();
    let mut out: Vec<CodeItem> = Vec::new();
    for child in children(root) {
        if !matches!(child.kind(), "expression_statement" | "assignment") {
            continue;
        }
        for name in global_names_python(child, src) {
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
}
