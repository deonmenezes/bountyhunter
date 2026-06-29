use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

fn sha_map(inventory: &Value) -> BTreeMap<String, Value> {
    inventory
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|file| {
            Some((
                file.get("path")?.as_str()?.to_string(),
                file.get("sha256").cloned().unwrap_or(Value::Null),
            ))
        })
        .collect()
}

fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn binary_sha(inventory: &Value) -> Value {
    inventory
        .get("binary")
        .and_then(Value::as_object)
        .and_then(|binary| binary.get("sha256"))
        .cloned()
        .unwrap_or(Value::Null)
}

pub fn compare_inventories(old: &Value, new: &Value) -> Option<Value> {
    let old_shas = sha_map(old);
    let new_shas = sha_map(new);
    if !old_shas.values().any(py_truthy) {
        return None;
    }

    let old_paths: BTreeSet<_> = old_shas.keys().cloned().collect();
    let new_paths: BTreeSet<_> = new_shas.keys().cloned().collect();
    let added: Vec<_> = new_paths.difference(&old_paths).cloned().collect();
    let removed: Vec<_> = old_paths.difference(&new_paths).cloned().collect();
    let modified: Vec<_> = old_paths
        .intersection(&new_paths)
        .filter(|path| {
            let old_sha = &old_shas[*path];
            let new_sha = &new_shas[*path];
            py_truthy(old_sha) && py_truthy(new_sha) && old_sha != new_sha
        })
        .cloned()
        .collect();

    let old_binary = binary_sha(old);
    let new_binary = binary_sha(new);
    let binary_changed =
        !(old_binary.is_null() && new_binary.is_null()) && old_binary != new_binary;
    if added.is_empty() && removed.is_empty() && modified.is_empty() && !binary_changed {
        return None;
    }

    let mut result = Map::new();
    result.insert(
        "source_changed".into(),
        Value::Bool(!added.is_empty() || !removed.is_empty() || !modified.is_empty()),
    );
    result.insert("binary_changed".into(), Value::Bool(binary_changed));
    result.insert("added".into(), json!(added));
    result.insert("removed".into(), json!(removed));
    result.insert("modified".into(), json!(modified));
    if binary_changed {
        result.insert("binary_old_sha256".into(), old_binary);
        result.insert("binary_new_sha256".into(), new_binary);
    }
    Some(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn source_diff_vectors_match_python() {
        let old = json!({"files": [{"path": "a.py", "sha256": "abc"}]});
        assert_eq!(compare_inventories(&old, &old), None);

        let new = json!({"files": [
            {"path": "a.py", "sha256": "xyz"},
            {"path": "b.py", "sha256": "def"}
        ]});
        let diff = compare_inventories(&old, &new).unwrap();
        assert_eq!(diff["added"], json!(["b.py"]));
        assert_eq!(diff["modified"], json!(["a.py"]));
        assert_eq!(diff["removed"], json!([]));
    }

    #[test]
    fn binary_presence_asymmetry_is_a_change() {
        let old = json!({"files": [{"path": "a", "sha256": "x"}]});
        let new = json!({
            "files": [{"path": "a", "sha256": "x"}],
            "binary": {"sha256": "bin"}
        });
        let diff = compare_inventories(&old, &new).unwrap();
        assert_eq!(diff["binary_changed"], true);
        assert_eq!(diff["binary_old_sha256"], Value::Null);
        assert_eq!(diff["binary_new_sha256"], "bin");
    }
}
