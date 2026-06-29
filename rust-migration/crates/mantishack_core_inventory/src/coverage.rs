use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

fn items_mut(file: &mut Value) -> Option<&mut Vec<Value>> {
    let object = file.as_object_mut()?;
    if object.contains_key("items") {
        object.get_mut("items")?.as_array_mut()
    } else {
        object.get_mut("functions")?.as_array_mut()
    }
}

fn items(file: &Value) -> &[Value] {
    file.get("items")
        .or_else(|| file.get("functions"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

pub fn update_coverage(
    inventory: &mut Value,
    checked_functions: &Value,
    source_label: &str,
) -> Value {
    let checked: BTreeSet<(String, String, String)> = checked_functions
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            Some((
                entry.get("file")?.as_str()?.to_string(),
                entry
                    .get("class")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                entry.get("function")?.as_str()?.to_string(),
            ))
        })
        .collect();

    if let Some(files) = inventory.get_mut("files").and_then(Value::as_array_mut) {
        for file in files {
            let path = match file.get("path").and_then(Value::as_str) {
                Some(path) if !path.is_empty() => path.to_string(),
                _ => continue,
            };
            let Some(file_items) = items_mut(file) else {
                continue;
            };
            for item in file_items {
                let name = match item.get("name").and_then(Value::as_str) {
                    Some(name) if !name.is_empty() => name.to_string(),
                    _ => continue,
                };
                let class = item
                    .get("class")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if !checked.contains(&(path.clone(), class, name.clone()))
                    && !checked.contains(&(path.clone(), String::new(), name))
                {
                    continue;
                }

                let object = match item.as_object_mut() {
                    Some(object) => object,
                    None => continue,
                };
                let checked_by = object
                    .entry("checked_by")
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Some(labels) = checked_by.as_array_mut() {
                    if !labels
                        .iter()
                        .any(|label| label.as_str() == Some(source_label))
                    {
                        labels.push(Value::String(source_label.to_string()));
                    }
                }
            }
        }
    }
    inventory.clone()
}

pub fn get_coverage_stats(inventory: &Value) -> Value {
    let mut total = 0_u64;
    let mut checked = 0_u64;
    let mut by_source: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_kind: BTreeMap<String, (u64, u64)> = BTreeMap::new();

    for file in inventory
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for item in items(file) {
            total += 1;
            let kind = item
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("function")
                .to_string();
            let counts = by_kind.entry(kind).or_default();
            counts.0 += 1;

            let checked_by = item
                .get("checked_by")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if !checked_by.is_empty() {
                checked += 1;
                counts.1 += 1;
                for source in checked_by.iter().filter_map(Value::as_str) {
                    *by_source.entry(source.to_string()).or_default() += 1;
                }
            }
        }
    }

    let function_counts = by_kind.get("function").copied().unwrap_or_default();
    let by_kind: Map<String, Value> = by_kind
        .into_iter()
        .map(|(kind, (total, checked))| (kind, json!({"total": total, "checked": checked})))
        .collect();
    let by_source: Map<String, Value> = by_source
        .into_iter()
        .map(|(source, count)| (source, json!(count)))
        .collect();

    json!({
        "total_items": total,
        "checked_items": checked,
        "total_functions": function_counts.0,
        "checked_functions": function_counts.1,
        "coverage_percent": if total > 0 { checked as f64 / total as f64 * 100.0 } else { 0.0 },
        "total_sloc": inventory.get("total_sloc").cloned().unwrap_or(json!(0)),
        "by_kind": by_kind,
        "by_source": by_source,
    })
}

fn comma_number(value: i64) -> String {
    let negative = value < 0;
    let digits = value.unsigned_abs().to_string();
    let mut output = String::new();
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            output.push(',');
        }
        output.push(character);
    }
    if negative {
        format!("-{output}")
    } else {
        output
    }
}

pub fn format_coverage_summary(inventory: &Value) -> String {
    let stats = get_coverage_stats(inventory);
    let total_files = inventory
        .get("total_files")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let excluded = inventory
        .get("excluded_files")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let sloc = stats.get("total_sloc").and_then(Value::as_i64).unwrap_or(0);

    let mut kind_parts = Vec::new();
    if let Some(kinds) = stats.get("by_kind").and_then(Value::as_object) {
        for (kind, counts) in kinds {
            let total = counts.get("total").and_then(Value::as_u64).unwrap_or(0);
            let label = match kind.as_str() {
                "function" => "functions".to_string(),
                "global" => "globals".to_string(),
                "macro" => "macros".to_string(),
                "class" => "classes".to_string(),
                other => format!("{other}s"),
            };
            kind_parts.push(format!("{total} {label}"));
        }
    }
    let items = if kind_parts.is_empty() {
        format!(
            "{} items",
            stats
                .get("total_items")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        )
    } else {
        kind_parts.join(", ")
    };

    let mut inventory_line = format!(
        "Inventory: {total_files} files, {} SLOC, {items}",
        comma_number(sloc)
    );
    if excluded > 0 {
        inventory_line.push_str(&format!(" ({excluded} excluded)"));
    }
    let mut lines = vec![inventory_line];

    let checked = stats
        .get("checked_items")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if checked > 0 {
        let total = stats
            .get("total_items")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let percent = stats
            .get("coverage_percent")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        lines.push(format!(
            "Coverage: {checked}/{total} items checked ({percent:.1}%)"
        ));
        if let Some(sources) = stats.get("by_source").and_then(Value::as_object) {
            for (source, count) in sources {
                lines.push(format!(
                    "  - {source}: {}",
                    count.as_u64().unwrap_or_default()
                ));
            }
        }
    }

    if let Some(limitations) = inventory.get("limitations").and_then(Value::as_array) {
        if !limitations.is_empty() {
            lines.push(format!(
                "Limitations: {}",
                limitations
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn stats_and_summary_match_python_shapes() {
        let inventory = json!({
            "total_files": 10,
            "total_sloc": 1234,
            "excluded_files": [{"path": "test.py"}],
            "files": [{"functions": [
                {"name": "foo", "checked_by": ["validate:stage-a"]},
                {"name": "bar", "checked_by": []},
                {"name": "baz", "checked_by": ["validate:stage-a", "understand:map"]}
            ]}]
        });
        let stats = get_coverage_stats(&inventory);
        assert_eq!(stats["total_functions"], 3);
        assert_eq!(stats["checked_functions"], 2);
        assert_eq!(stats["by_source"]["validate:stage-a"], 2);
        assert_eq!(stats["by_source"]["understand:map"], 1);
        let summary = format_coverage_summary(&inventory);
        assert!(summary.contains("10 files, 1,234 SLOC"));
        assert!(summary.contains("2/3 items checked (66.7%)"));
        assert!(summary.contains("(1 excluded)"));
    }

    #[test]
    fn update_mutates_and_deduplicates() {
        let mut inventory = json!({"files": [{
            "path": "app.py",
            "functions": [{"name": "foo", "checked_by": []}]
        }]});
        let checked = json!([{"file": "app.py", "function": "foo"}]);
        update_coverage(&mut inventory, &checked, "validate:stage-a");
        update_coverage(&mut inventory, &checked, "validate:stage-a");
        assert_eq!(
            inventory["files"][0]["functions"][0]["checked_by"],
            json!(["validate:stage-a"])
        );
    }
}
