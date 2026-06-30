//! Tree-sitter parsing foundation for the inventory migration.
//!
//! Mirrors the role of `_ts_language` / `_ts_parser_for` in
//! `core/inventory/extractors.py`: it maps a language name to a grammar and
//! hands back a ready parser. The inventory extractors, call graph, and
//! reachability ports all parse through this crate so they share one grammar
//! version set (pinned to match the Python oracle's installed grammars).
//!
//! Languages are added incrementally as each extractor branch is ported.

use tree_sitter::{Language, Parser, Tree};

/// Language names recognised so far. Grows as extractor branches are ported.
pub const SUPPORTED_LANGUAGES: &[&str] =
    &["python", "javascript", "c", "cpp", "go", "java", "rust", "ruby", "typescript", "tsx"];

/// The tree-sitter [`Language`] for a language name, or `None` if no grammar is
/// wired yet (graceful degradation — callers treat absence as "no parse",
/// matching the Python `_ts_language` returning `None`). Grammar choice matches
/// the Python `_ts_language` mapping.
pub fn language_for(language: &str) -> Option<Language> {
    match language {
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "c" => Some(tree_sitter_c::LANGUAGE.into()),
        "cpp" => Some(tree_sitter_cpp::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        "ruby" => Some(tree_sitter_ruby::LANGUAGE.into()),
        // `.ts` and `.tsx` need different grammars (the typescript grammar
        // parses `<T>x` casts but errors on JSX; tsx is the reverse).
        "typescript" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        _ => None,
    }
}

/// A parser configured for `language`, or `None` if the grammar isn't wired.
pub fn parser_for(language: &str) -> Option<Parser> {
    let lang = language_for(language)?;
    let mut parser = Parser::new();
    parser.set_language(&lang).ok()?;
    Some(parser)
}

/// Parse `source` as `language`, returning the syntax tree (or `None` if the
/// grammar isn't wired or parsing fails). UTF-8 bytes, matching the Python
/// `parser.parse(content.encode())`.
pub fn parse(language: &str, source: &str) -> Option<Tree> {
    let mut parser = parser_for(language)?;
    parser.parse(source.as_bytes(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_language_is_none() {
        assert!(language_for("cobol").is_none());
        assert!(parser_for("cobol").is_none());
        assert!(parse("cobol", "x").is_none());
    }

    #[test]
    fn all_wired_languages_parse() {
        // Each wired grammar parses a trivial snippet without error.
        let cases = [
            ("python", "x = 1\n"),
            ("javascript", "const x = 1;\n"),
            ("c", "int x;\n"),
            ("go", "package main\n"),
            ("java", "class A {}\n"),
            ("typescript", "const x: number = 1;\n"),
            ("tsx", "const x = <div/>;\n"),
        ];
        for (lang, src) in cases {
            let tree = parse(lang, src).unwrap_or_else(|| panic!("parse {lang}"));
            assert!(!tree.root_node().has_error(), "{lang} parsed with errors");
        }
    }

    #[test]
    fn python_parses_to_a_module() {
        let tree = parse("python", "def foo(a, b):\n    return a + b\n").expect("parse");
        let root = tree.root_node();
        assert_eq!(root.kind(), "module");
        assert!(!root.has_error());
    }

    #[test]
    fn javascript_parses_and_finds_function() {
        let tree = parse("javascript", "function add(a, b) { return a + b; }\n").expect("parse");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error());
        let mut cursor = root.walk();
        let has_func = root
            .children(&mut cursor)
            .any(|c| c.kind() == "function_declaration");
        assert!(has_func);
    }

    #[test]
    fn python_finds_function_definition_with_correct_lines() {
        let src = "import os\n\ndef foo(a):\n    return a\n";
        let tree = parse("python", src).expect("parse");
        let root = tree.root_node();
        // Walk the top-level children for a function_definition.
        let mut found = None;
        let mut cursor = root.walk();
        for child in root.children(&mut cursor) {
            if child.kind() == "function_definition" {
                found = Some(child);
            }
        }
        let func = found.expect("function_definition present");
        // tree-sitter rows are 0-based; the Python extractor reports +1.
        assert_eq!(func.start_position().row + 1, 3);
        // The function name node, by field.
        let name = func.child_by_field_name("name").expect("name field");
        assert_eq!(name.utf8_text(src.as_bytes()).unwrap(), "foo");
    }
}
