//! Gradle version catalog parser — Rust port of the parse core of
//! `packages/sca/parsers/gradle_version_catalog.py`. Parses a
//! `libs.versions.toml` into a `VersionCatalog` (versions / libraries / plugins
//! / bundles). The filesystem read + per-process cache + `find_default_catalog`
//! are out of scope; this takes already-read content.

use serde_json::{json, Map, Value};

use crate::toml_util::parse_toml;

#[derive(Clone, Debug, PartialEq)]
pub struct CatalogLibrary {
    pub alias: String,
    pub group: String,
    pub artifact: String,
    pub version: Option<String>,
    pub version_via_ref: bool,
    pub version_ref_name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CatalogPlugin {
    pub alias: String,
    pub plugin_id: String,
    pub version: Option<String>,
    pub version_via_ref: bool,
    pub version_ref_name: String,
}

/// `[versions]` -> `{name: version}` (string non-empty values only).
fn parse_versions(raw: &Value) -> Map<String, Value> {
    let mut out = Map::new();
    if let Some(obj) = raw.as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    out.insert(k.clone(), json!(s));
                }
            }
        }
    }
    out
}

fn parse_library_string(alias: &str, coord: &str) -> Option<CatalogLibrary> {
    let parts: Vec<&str> = coord.split(':').collect();
    if parts.len() < 2 {
        return None;
    }
    Some(CatalogLibrary {
        alias: alias.to_string(),
        group: parts[0].to_string(),
        artifact: parts[1].to_string(),
        version: parts.get(2).map(|s| s.to_string()),
        version_via_ref: false,
        version_ref_name: String::new(),
    })
}

fn parse_library_table(alias: &str, entry: &Map<String, Value>, versions: &Map<String, Value>) -> Option<CatalogLibrary> {
    let (group, artifact) = match entry.get("module").and_then(Value::as_str) {
        Some(m) if m.contains(':') => {
            let (g, a) = m.split_once(':').unwrap();
            (g.to_string(), a.to_string())
        }
        _ => {
            let g = entry.get("group").and_then(Value::as_str);
            let n = entry.get("name").and_then(Value::as_str);
            match (g, n) {
                (Some(g), Some(n)) => (g.to_string(), n.to_string()),
                _ => return None,
            }
        }
    };

    let mut version: Option<String> = None;
    let mut via_ref = false;
    let mut ref_name = String::new();
    match entry.get("version") {
        Some(Value::String(s)) => version = Some(s.clone()),
        Some(v) if v.is_object() => {
            let vobj = v.as_object().unwrap();
            if let Some(ref_) = vobj.get("ref").and_then(Value::as_str) {
                via_ref = true;
                ref_name = ref_.to_string();
                version = versions.get(ref_).and_then(Value::as_str).map(str::to_string);
            } else {
                for k in ["strictly", "require", "prefer"] {
                    if let Some(v) = vobj.get(k).and_then(Value::as_str) {
                        if !v.is_empty() {
                            version = Some(v.to_string());
                            break;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Some(CatalogLibrary { alias: alias.to_string(), group, artifact, version, version_via_ref: via_ref, version_ref_name: ref_name })
}

fn parse_libraries(raw: &Value, versions: &Map<String, Value>) -> Vec<CatalogLibrary> {
    let mut out = Vec::new();
    if let Some(obj) = raw.as_object() {
        for (alias, entry) in obj {
            let lib = match entry {
                Value::String(s) => parse_library_string(alias, s),
                e if e.is_object() => parse_library_table(alias, e.as_object().unwrap(), versions),
                _ => None,
            };
            if let Some(lib) = lib {
                out.push(lib);
            }
        }
    }
    out
}

fn parse_plugins(raw: &Value, versions: &Map<String, Value>) -> Vec<CatalogPlugin> {
    let mut out = Vec::new();
    let Some(obj) = raw.as_object() else { return out };
    for (alias, entry) in obj {
        match entry {
            Value::String(s) => {
                if let Some((plugin_id, version)) = s.split_once(':') {
                    out.push(CatalogPlugin {
                        alias: alias.clone(),
                        plugin_id: plugin_id.to_string(),
                        version: Some(version.to_string()),
                        version_via_ref: false,
                        version_ref_name: String::new(),
                    });
                }
            }
            e if e.is_object() => {
                let eo = e.as_object().unwrap();
                let Some(plugin_id) = eo.get("id").and_then(Value::as_str) else { continue };
                let mut version: Option<String> = None;
                let mut via_ref = false;
                let mut ref_name = String::new();
                match eo.get("version") {
                    Some(Value::String(s)) => version = Some(s.clone()),
                    Some(v) if v.is_object() => {
                        if let Some(ref_) = v.get("ref").and_then(Value::as_str) {
                            via_ref = true;
                            ref_name = ref_.to_string();
                            version = versions.get(ref_).and_then(Value::as_str).map(str::to_string);
                        }
                    }
                    _ => {}
                }
                out.push(CatalogPlugin {
                    alias: alias.clone(),
                    plugin_id: plugin_id.to_string(),
                    version,
                    version_via_ref: via_ref,
                    version_ref_name: ref_name,
                });
            }
            _ => {}
        }
    }
    out
}

fn parse_bundles(raw: &Value) -> Map<String, Value> {
    let mut out = Map::new();
    if let Some(obj) = raw.as_object() {
        for (alias, entry) in obj {
            if let Some(arr) = entry.as_array() {
                if arr.iter().all(Value::is_string) {
                    out.insert(alias.clone(), Value::Array(arr.clone()));
                }
            }
        }
    }
    out
}

fn lib_json(l: &CatalogLibrary) -> Value {
    json!({
        "alias": l.alias, "group": l.group, "artifact": l.artifact,
        "version": l.version, "version_via_ref": l.version_via_ref,
        "version_ref_name": l.version_ref_name,
    })
}
fn plugin_json(p: &CatalogPlugin) -> Value {
    json!({
        "alias": p.alias, "plugin_id": p.plugin_id, "version": p.version,
        "version_via_ref": p.version_via_ref, "version_ref_name": p.version_ref_name,
    })
}

/// Parse a `libs.versions.toml` into a catalog JSON view (`parse_libs_versions_toml`).
/// `None` on malformed TOML.
pub fn parse_libs_versions_toml(content: &str) -> Option<Value> {
    let data = parse_toml(content)?;
    if !data.is_object() {
        return None;
    }
    let empty = json!({});
    let versions = parse_versions(data.get("versions").unwrap_or(&empty));
    let libraries = parse_libraries(data.get("libraries").unwrap_or(&empty), &versions);
    let plugins = parse_plugins(data.get("plugins").unwrap_or(&empty), &versions);
    let bundles = parse_bundles(data.get("bundles").unwrap_or(&empty));

    let libs_map: Map<String, Value> = libraries.iter().map(|l| (l.alias.clone(), lib_json(l))).collect();
    let plugins_map: Map<String, Value> = plugins.iter().map(|p| (p.alias.clone(), plugin_json(p))).collect();
    Some(json!({
        "versions": versions,
        "libraries": libs_map,
        "plugins": plugins_map,
        "bundles": bundles,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_sections() {
        let src = r#"
[versions]
spring = "6.1.2"
junit = "5.10.1"

[libraries]
spring-core = { module = "org.springframework:spring-core", version.ref = "spring" }
junit = { group = "org.junit.jupiter", name = "junit-jupiter", version.ref = "junit" }
guava = "com.google.guava:guava:33.0.0"
missingref = { module = "x:y", version.ref = "nope" }

[plugins]
shadow = "com.github.johnrengelman.shadow:8.1.1"
boot = { id = "org.springframework.boot", version.ref = "spring" }

[bundles]
testing = ["junit", "guava"]
"#;
        let cat = parse_libs_versions_toml(src).unwrap();
        assert_eq!(cat["versions"]["spring"], "6.1.2");
        assert_eq!(cat["libraries"]["spring-core"]["version"], "6.1.2");
        assert_eq!(cat["libraries"]["spring-core"]["version_via_ref"], true);
        assert_eq!(cat["libraries"]["spring-core"]["version_ref_name"], "spring");
        assert_eq!(cat["libraries"]["guava"]["version"], "33.0.0");
        // missing ref -> via_ref true but version null.
        assert_eq!(cat["libraries"]["missingref"]["version"], Value::Null);
        assert_eq!(cat["libraries"]["missingref"]["version_via_ref"], true);
        assert_eq!(cat["plugins"]["shadow"]["version"], "8.1.1");
        assert_eq!(cat["plugins"]["boot"]["version"], "6.1.2");
        assert_eq!(cat["bundles"]["testing"], json!(["junit", "guava"]));
    }
}
