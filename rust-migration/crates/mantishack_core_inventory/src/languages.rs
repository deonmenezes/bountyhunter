use std::path::Path;

pub const LANGUAGE_MAP: &[(&str, &str)] = &[
    (".py", "python"),
    (".js", "javascript"),
    (".jsx", "javascript"),
    (".ts", "typescript"),
    (".tsx", "tsx"),
    (".c", "c"),
    (".h", "c"),
    (".cpp", "cpp"),
    (".cc", "cpp"),
    (".cxx", "cpp"),
    (".hpp", "cpp"),
    (".java", "java"),
    (".go", "go"),
    (".rs", "rust"),
    (".rb", "ruby"),
    (".php", "php"),
    (".cs", "csharp"),
    (".swift", "swift"),
    (".kt", "kotlin"),
    (".scala", "scala"),
];

pub fn detect_language(filepath: &str) -> Option<&'static str> {
    let extension = Path::new(filepath)
        .extension()?
        .to_string_lossy()
        .to_ascii_lowercase();
    let dotted = format!(".{extension}");
    LANGUAGE_MAP
        .iter()
        .find_map(|(suffix, language)| (*suffix == dotted).then_some(*language))
}

#[cfg(feature = "python")]
pub fn language_map_py(py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
    use pyo3::types::{PyDict, PyDictMethods};

    let map = PyDict::new_bound(py);
    for (suffix, language) in LANGUAGE_MAP {
        map.set_item(suffix, language)?;
    }
    Ok(map.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_vectors_match_python() {
        let cases = [
            ("foo.py", Some("python")),
            ("bar.jsx", Some("javascript")),
            ("baz.tsx", Some("tsx")),
            ("header.h", Some("c")),
            ("main.CPP", Some("cpp")),
            ("App.java", Some("java")),
            ("main.go", Some("go")),
            ("main.rs", Some("rust")),
            ("readme.md", None),
            ("noext", None),
        ];
        for (path, expected) in cases {
            assert_eq!(detect_language(path), expected, "{path}");
        }
    }
}
