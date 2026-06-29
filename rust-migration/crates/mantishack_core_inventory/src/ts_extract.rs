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

/// Extract functions from Python `content` via tree-sitter, matching the
/// Python `TreeSitterExtractor.extract` for the Python branch. Returns an empty
/// vec if parsing fails (caller falls back), mirroring the Python behaviour.
pub fn extract_python_functions(content: &str) -> Vec<FunctionInfo> {
    let Some(tree) = mantishack_ts::parse("python", content) else {
        return Vec::new();
    };
    let src = content.as_bytes();
    let mut out: Vec<FunctionInfo> = Vec::new();
    walk(tree.root_node(), src, &mut out, None, &[]);
    out
}

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
    out: &mut Vec<FunctionInfo>,
    class_name: Option<&str>,
    class_attributes: &[String],
) {
    for child in children(node) {
        match child.kind() {
            "class_definition" => {
                let cname = get_name(child, src);
                // Python: class_attributes = ts_decorators (JS/TS only) +
                // class_annotations (modifiers/superclass — none for Python) = [].
                walk(child, src, out, cname.as_deref(), &[]);
            }
            "function_definition" => {
                let mut attrs: Vec<String> = Vec::new();
                if let Some(parent) = child.parent() {
                    if parent.kind() == "decorated_definition" {
                        for sib in children(parent) {
                            if sib.kind() == "decorator" {
                                attrs.push(lstrip_at(text(sib, src)));
                            }
                        }
                    }
                }
                if let Some(fi) = extract_function(child, src, class_name, attrs, class_attributes) {
                    out.push(fi);
                }
                walk(child, src, out, class_name, class_attributes);
            }
            // Python: walk into the decorated wrapper (the inner
            // function_definition handles decorator collection via its parent).
            "decorated_definition" => walk(child, src, out, class_name, class_attributes),
            _ => walk(child, src, out, class_name, class_attributes),
        }
    }
}

/// `str.lstrip("@")` — strip leading `@` only (no other whitespace).
fn lstrip_at(s: &str) -> String {
    s.trim_start_matches('@').to_string()
}

/// Python branch of `_get_name`: the first `identifier`/`name` child.
fn get_name(node: Node, src: &[u8]) -> Option<String> {
    for child in children(node) {
        if matches!(child.kind(), "identifier" | "name") {
            return Some(text(child, src).to_string());
        }
    }
    None
}

fn extract_function(
    node: Node,
    src: &[u8],
    class_name: Option<&str>,
    attrs: Vec<String>,
    class_attributes: &[String],
) -> Option<FunctionInfo> {
    let name = get_name(node, src)?;
    // Python branch: visibility stays None and class_name is unchanged
    // (the modifiers/storage-class/go branches don't apply to Python).
    let parameters = extract_parameters(node, src);
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
            class_name: class_name.map(str::to_string),
            visibility: None,
            attributes: attrs,
            return_type,
            parameters,
            class_attributes: class_attributes.to_vec(),
        }),
        checked_by: Vec::new(),
    })
}

fn extract_parameters(node: Node, src: &[u8]) -> Vec<(String, Option<String>)> {
    let mut params: Vec<(String, Option<String>)> = Vec::new();
    for child in children(node) {
        if matches!(child.kind(), "parameters" | "formal_parameters" | "parameter_list") {
            for param in children(child) {
                if let (Some(name), ptype) = parse_param(param, src) {
                    if !matches!(name.as_str(), "(" | ")" | "," | "self" | "this") {
                        params.push((name, ptype));
                    }
                }
            }
        }
    }
    params
}

fn parse_param(node: Node, src: &[u8]) -> (Option<String>, Option<String>) {
    let mut name: Option<String> = None;
    let mut ptype: Option<String> = None;
    for child in children(node) {
        let k = child.kind();
        if matches!(k, "identifier" | "name") {
            name = Some(text(child, src).to_string());
        } else if TYPE_NODE_KINDS.contains(&k) {
            ptype = Some(lstrip_colon_space(text(child, src)));
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
    // Python has no function_declarator, so func_decl_pos is None and only the
    // ("type"|"return_type") branch can fire.
    for child in children(node) {
        if matches!(child.kind(), "type" | "return_type") {
            return Some(lstrip_colon_space(text(child, src)));
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
}
