//! Maven POM parser — Rust port of `packages/sca/parsers/pom.py` (single-file).
//! Walks dependencies / dependencyManagement / plugins / parent, resolves
//! top-level `${...}` properties + local dependencyManagement versions. The
//! opt-in cross-file inheritance resolver defaults to a no-op (network/
//! filesystem), so this content-based port matches the default behaviour. Takes
//! already-read content; roxmltree local tag names match `_strip_namespaces`.

use std::sync::OnceLock;

use regex::Regex;
use roxmltree::{Document, Node};
use serde_json::{json, Map, Value};

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "Maven";

const SCOPE_MAP: &[(&str, &str)] = &[
    ("compile", "main"), ("runtime", "main"), ("provided", "provided"),
    ("system", "system"), ("test", "test"), ("import", "build"),
];

fn property_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\$\{([^}]+)\}").unwrap())
}

fn child_elements<'a, 'i>(node: Node<'a, 'i>) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children().filter(roxmltree::Node::is_element)
}

fn find_child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    child_elements(node).find(|c| c.tag_name().name() == name)
}

fn find_all<'a, 'i>(root: Node<'a, 'i>, path: &[&str]) -> Vec<Node<'a, 'i>> {
    let mut current = vec![root];
    for seg in path {
        let mut next = Vec::new();
        for n in current {
            next.extend(child_elements(n).filter(|c| c.tag_name().name() == *seg));
        }
        current = next;
    }
    current
}

fn text(el: Node, tag: &str) -> Option<String> {
    find_child(el, tag).and_then(|c| c.text()).map(str::to_string)
}

fn scope_map(raw: &str) -> &'static str {
    SCOPE_MAP.iter().find(|(k, _)| *k == raw).map_or("main", |(_, v)| *v)
}

fn build_purl(group: &str, artifact: &str, version: Option<&str>) -> String {
    let base = format!("pkg:maven/{group}/{artifact}");
    match version {
        Some(v) => format!("{base}@{v}"),
        None => base,
    }
}

fn resolve(value: Option<&str>, properties: &Map<String, Value>) -> (Option<String>, bool) {
    let Some(value) = value else { return (None, true) };
    let text = value.trim();
    if text.is_empty() {
        return (None, true);
    }
    let mut fully = true;
    let mut out = String::new();
    let mut last = 0;
    for m in property_re().captures_iter(text) {
        let whole = m.get(0).unwrap();
        out.push_str(&text[last..whole.start()]);
        match properties.get(&m[1]).and_then(Value::as_str) {
            Some(v) => out.push_str(v),
            None => {
                fully = false;
                out.push_str(whole.as_str());
            }
        }
        last = whole.end();
    }
    out.push_str(&text[last..]);
    (Some(out), fully)
}

fn collect_properties(root: Node) -> Map<String, Value> {
    let mut props = Map::new();
    if let Some(props_el) = find_child(root, "properties") {
        for child in child_elements(props_el) {
            if let Some(t) = child.text() {
                props.insert(child.tag_name().name().to_string(), json!(t.trim()));
            }
        }
    }
    for (key, tag) in [("project.version", "version"), ("project.groupId", "groupId"), ("project.artifactId", "artifactId")] {
        if let Some(el) = find_child(root, tag) {
            if let Some(t) = el.text() {
                if !t.is_empty() {
                    props.entry(key.to_string()).or_insert_with(|| json!(t.trim()));
                }
            }
        }
        if !props.contains_key(key) {
            if let Some(par) = find_child(root, "parent") {
                if let Some(el) = find_child(par, tag) {
                    if let Some(t) = el.text() {
                        if !t.is_empty() {
                            props.insert(key.to_string(), json!(t.trim()));
                        }
                    }
                }
            }
        }
    }
    props
}

fn extract_license(root: Node) -> Option<String> {
    let names: Vec<String> = find_all(root, &["licenses", "license"])
        .into_iter()
        .filter_map(|el| text(el, "name"))
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .collect();
    match names.len() {
        0 => None,
        1 => Some(names.into_iter().next().unwrap()),
        _ => Some(names.join(" OR ")),
    }
}

fn classify_version(version: Option<&str>) -> (PinStyle, Option<String>) {
    let Some(v) = version else { return (PinStyle::Unknown, None) };
    let v = v.trim();
    if v.is_empty() {
        return (PinStyle::Unknown, None);
    }
    if v.contains("${") {
        return (PinStyle::Unknown, Some(v.to_string()));
    }
    if matches!(v, "LATEST" | "RELEASE" | "*") {
        return (PinStyle::Wildcard, Some(v.to_string()));
    }
    if v.starts_with('[') && v.ends_with(']') && !v.contains(',') {
        return (PinStyle::Exact, Some(v[1..v.len() - 1].to_string()));
    }
    if v.contains(['[', ']', '(', ')', ',']) {
        return (PinStyle::Range, Some(v.to_string()));
    }
    (PinStyle::Exact, Some(v.to_string()))
}

fn confidence(fully_resolved: bool, version: Option<&str>, is_managed: bool) -> Confidence {
    if !fully_resolved {
        Confidence::new("medium", "POM property substitution incomplete")
    } else if version.is_none() {
        Confidence::new("medium", "POM dependency has no resolvable version")
    } else if is_managed {
        Confidence::new("high", "POM dependencyManagement entry")
    } else {
        Confidence::new("high", "POM dependency block")
    }
}

fn build_dep(el: Node, declared_in: &str, properties: &Map<String, Value>, scope_default: &str, is_managed: bool, is_plugin: bool) -> Option<Dependency> {
    let (group, group_ok) = resolve(text(el, "groupId").as_deref(), properties);
    let (artifact, artifact_ok) = resolve(text(el, "artifactId").as_deref(), properties);
    let (version, version_ok) = resolve(text(el, "version").as_deref(), properties);
    let scope_text = text(el, "scope");

    let artifact = artifact.filter(|a| !a.is_empty())?;
    let (group, group_ok) = match group.filter(|g| !g.is_empty()) {
        Some(g) => (g, group_ok),
        None => {
            if is_plugin {
                ("org.apache.maven.plugins".to_string(), true)
            } else {
                return None;
            }
        }
    };

    let name = format!("{group}:{artifact}");
    let (pin_style, version_for_record) = classify_version(version.as_deref());
    let fully_resolved = group_ok && artifact_ok && version_ok;

    let raw_scope = scope_text.as_deref().unwrap_or(scope_default).trim().to_lowercase();
    let mut scope = scope_map(&raw_scope).to_string();
    if is_plugin {
        scope = "build".to_string();
    }
    if is_managed && !is_plugin && raw_scope != "import" {
        scope = "build".to_string();
    }

    Some(Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        purl: build_purl(&group, &artifact, version_for_record.as_deref()),
        parser_confidence: confidence(fully_resolved, version_for_record.as_deref(), is_managed),
        name,
        version: version_for_record,
        declared_in: declared_in.to_string(),
        scope,
        is_lockfile: false,
        pin_style,
        direct: !is_managed,
        declared_license: None,
        commented_out: false,
        source_kind: "manifest".to_string(),
        source_extra: None,
    })
}

fn resolve_local_dep_management(deps: &mut [Dependency]) {
    let mut managed: Map<String, Value> = Map::new();
    for d in deps.iter() {
        if d.scope == "build" {
            if let Some(v) = &d.version {
                managed.insert(d.name.clone(), json!(v));
            }
        }
    }
    for d in deps.iter_mut() {
        if d.scope == "build" || d.version.is_some() {
            continue;
        }
        if let Some(v) = managed.get(&d.name).and_then(Value::as_str) {
            d.version = Some(v.to_string());
        }
    }
}

/// Parse a `pom.xml` (`parse`): all declared dependencies.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(doc) = Document::parse(content) else { return Vec::new() };
    let root = doc.root_element();
    let properties = collect_properties(root);
    let project_license = extract_license(root);
    let mut deps: Vec<Dependency> = Vec::new();

    for el in find_all(root, &["dependencies", "dependency"]) {
        if let Some(mut d) = build_dep(el, declared_in, &properties, "compile", false, false) {
            d.declared_license = project_license.clone();
            deps.push(d);
        }
    }
    for el in find_all(root, &["dependencyManagement", "dependencies", "dependency"]) {
        if let Some(mut d) = build_dep(el, declared_in, &properties, "import", true, false) {
            d.declared_license = project_license.clone();
            deps.push(d);
        }
    }
    for path in [
        &["build", "plugins", "plugin"][..],
        &["build", "pluginManagement", "plugins", "plugin"][..],
        &["reporting", "plugins", "plugin"][..],
    ] {
        for el in find_all(root, path) {
            if let Some(d) = build_dep(el, declared_in, &properties, "build", false, true) {
                deps.push(d);
            }
        }
    }
    if let Some(parent) = find_child(root, "parent") {
        if let Some(mut d) = build_dep(parent, declared_in, &properties, "build", false, false) {
            d.scope = "build".to_string();
            deps.push(d);
        }
    }

    resolve_local_dep_management(&mut deps);
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pom_dependencies() {
        let src = r#"<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <properties>
    <spring.version>6.1.2</spring.version>
  </properties>
  <licenses>
    <license><name>Apache-2.0</name></license>
  </licenses>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>${spring.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>"#;
        let deps = parse(src, "pom.xml");
        let direct: Vec<_> = deps.iter().filter(|d| d.direct).collect();
        let spring = direct.iter().find(|d| d.name == "org.springframework:spring-core").unwrap();
        // version inherited from local dependencyManagement (${spring.version} resolved).
        assert_eq!(spring.version.as_deref(), Some("6.1.2"));
        assert_eq!(spring.declared_license.as_deref(), Some("Apache-2.0"));
        let junit = direct.iter().find(|d| d.name == "junit:junit").unwrap();
        assert_eq!(junit.scope, "test");
        // The managed entry is recorded as build scope (version constraint).
        assert!(deps.iter().any(|d| d.name == "org.springframework:spring-core" && d.scope == "build"));
    }
}
