use std::path::{Component, Path};

use serde_json::Value;

fn lexical_normalise(path: &str) -> String {
    let path = Path::new(path);
    let absolute = path.is_absolute();
    let mut parts: Vec<String> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.last().map(String::as_str) != Some("..") && !parts.is_empty() {
                    parts.pop();
                } else if !absolute {
                    parts.push("..".into());
                }
            }
            Component::RootDir => {}
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::Prefix(prefix) => {
                parts.push(prefix.as_os_str().to_string_lossy().into_owned())
            }
        }
    }
    let joined = parts.join(std::path::MAIN_SEPARATOR_STR);
    if absolute {
        format!("{}{}", std::path::MAIN_SEPARATOR, joined)
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

fn relative_path(path: &str, root: &str) -> String {
    let path = Path::new(path);
    let root = Path::new(root);
    match path.strip_prefix(root) {
        Ok(relative) => relative.to_string_lossy().into_owned(),
        Err(_) => {
            // Python os.path.relpath permits paths outside the root.
            let path_parts: Vec<_> = path.components().collect();
            let root_parts: Vec<_> = root.components().collect();
            let common = path_parts
                .iter()
                .zip(&root_parts)
                .take_while(|(left, right)| left == right)
                .count();
            let output = vec![".."; root_parts.len().saturating_sub(common)];
            let remainder: Vec<String> = path_parts[common..]
                .iter()
                .filter_map(|component| match component {
                    Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
                    _ => None,
                })
                .collect();
            let mut result = output.join(std::path::MAIN_SEPARATOR_STR);
            if !result.is_empty() && !remainder.is_empty() {
                result.push(std::path::MAIN_SEPARATOR);
            }
            result.push_str(&remainder.join(std::path::MAIN_SEPARATOR_STR));
            result
        }
    }
}

pub fn normalise_path(path: &str, repo_root: &str) -> String {
    let path = path.strip_prefix("file://").unwrap_or(path);
    let path = if Path::new(path).is_absolute() {
        relative_path(path, repo_root)
    } else {
        path.to_string()
    };
    lexical_normalise(&path)
}

pub fn lookup_function(
    checklist: &Value,
    file_path: &str,
    line: i64,
    repo_root: &str,
) -> Result<Option<Value>, String> {
    if checklist.is_null()
        || checklist.as_object().map(|value| value.is_empty()) == Some(true)
        || file_path.is_empty()
        || line == 0
    {
        return Ok(None);
    }
    let after_scheme = file_path.strip_prefix("file://").unwrap_or(file_path);
    if Path::new(after_scheme).is_absolute() && repo_root.is_empty() {
        return Err(format!(
            "lookup_function: absolute file_path={file_path:?} requires non-empty repo_root for normalisation"
        ));
    }
    let normalized = normalise_path(file_path, repo_root);
    let mut best_fuzzy: Option<Value> = None;

    for file in checklist
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let entry_path = normalise_path(
            file.get("path").and_then(Value::as_str).unwrap_or(""),
            repo_root,
        );
        if entry_path != normalized {
            continue;
        }
        let functions = file
            .get("items")
            .or_else(|| file.get("functions"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        for function in functions {
            if function
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("function")
                != "function"
            {
                continue;
            }
            let start = function
                .get("line_start")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if start > line {
                continue;
            }
            if let Some(end) = function.get("line_end").and_then(Value::as_i64) {
                if end >= line {
                    return Ok(Some(function.clone()));
                }
            } else if best_fuzzy
                .as_ref()
                .and_then(|best| best.get("line_start"))
                .and_then(Value::as_i64)
                .unwrap_or(0)
                < start
            {
                best_fuzzy = Some(function.clone());
            }
        }
    }
    Ok(best_fuzzy)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn checklist() -> Value {
        json!({"files": [
            {"path": "src/handler.py", "functions": [
                {"name": "setup", "line_start": 5, "line_end": 15},
                {"name": "process", "line_start": 20, "line_end": 50}
            ]},
            {"path": "src/legacy.py", "functions": [
                {"name": "old", "line_start": 1},
                {"name": "newer", "line_start": 50}
            ]}
        ]})
    }

    #[test]
    fn path_vectors_match_python() {
        assert_eq!(normalise_path("src/handler.py", "/repo"), "src/handler.py");
        assert_eq!(
            normalise_path("/repo/src/handler.py", "/repo"),
            "src/handler.py"
        );
        assert_eq!(
            normalise_path("file:///repo/src/handler.py", "/repo"),
            "src/handler.py"
        );
        assert_eq!(
            normalise_path("./src/handler.py", "/repo"),
            "src/handler.py"
        );
    }

    #[test]
    fn exact_and_fuzzy_lookup_match_python() {
        let checklist = checklist();
        assert_eq!(
            lookup_function(&checklist, "src/handler.py", 30, "")
                .unwrap()
                .unwrap()["name"],
            "process"
        );
        assert_eq!(
            lookup_function(&checklist, "src/legacy.py", 75, "")
                .unwrap()
                .unwrap()["name"],
            "newer"
        );
        assert_eq!(
            lookup_function(&checklist, "src/handler.py", 17, "").unwrap(),
            None
        );
    }

    #[test]
    fn absolute_lookup_requires_root() {
        assert!(lookup_function(&checklist(), "/repo/src/handler.py", 30, "").is_err());
    }
}
