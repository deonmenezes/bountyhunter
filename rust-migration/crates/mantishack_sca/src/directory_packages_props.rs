//! .NET Central Package Management parser — Rust port of the parse core of
//! `packages/sca/parsers/directory_packages_props.py`. Parses a
//! `Directory.Packages.props` into a `CPMFile` (cpm_enabled + central package
//! versions). The filesystem read + per-process cache + `find_cpm_chain` are out
//! of scope; this takes already-read content. roxmltree's local tag names match
//! the Python `_strip_namespace`.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use roxmltree::{Document, Node};
use serde_json::{json, Value};

fn msbuild_prop_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[$@%]\([^)]+\)").unwrap())
}

fn child_elements<'a, 'input>(node: Node<'a, 'input>) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children().filter(roxmltree::Node::is_element)
}

fn extract_cpm_enabled(root: Node) -> bool {
    let mut enabled = true;
    for pg in child_elements(root).filter(|n| n.tag_name().name() == "PropertyGroup") {
        for child in child_elements(pg) {
            if child.tag_name().name() != "ManagePackageVersionsCentrally" {
                continue;
            }
            let text = child.text().unwrap_or("").trim().to_lowercase();
            enabled = !matches!(text.as_str(), "false");
            // true / "" / unrecognised -> true; only "false" disables.
        }
    }
    enabled
}

fn extract_package_versions(root: Node) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut by_lower: HashMap<String, usize> = HashMap::new();
    for ig in child_elements(root).filter(|n| n.tag_name().name() == "ItemGroup") {
        for el in child_elements(ig) {
            let tag = el.tag_name().name();
            let is_global = tag == "GlobalPackageReference";
            if !is_global && tag != "PackageVersion" {
                continue;
            }
            let name = el.attribute("Include").unwrap_or("").trim();
            if name.is_empty() {
                continue;
            }
            let mut version: Option<String> = el.attribute("Version").map(str::to_string);
            if version.is_none() {
                if let Some(child) = child_elements(el).find(|c| c.tag_name().name() == "Version") {
                    if let Some(t) = child.text() {
                        if !t.is_empty() {
                            version = Some(t.trim().to_string());
                        }
                    }
                }
            }
            let Some(version) = version.filter(|v| !v.is_empty()) else { continue };
            if msbuild_prop_re().is_match(&version) {
                continue;
            }
            let entry = json!({"name": name, "version": version, "is_global": is_global});
            let lower = name.to_lowercase();
            if let Some(&i) = by_lower.get(&lower) {
                out[i] = entry;
            } else {
                by_lower.insert(lower, out.len());
                out.push(entry);
            }
        }
    }
    out
}

/// Parse a `Directory.Packages.props` (`parse_directory_packages_props`).
/// `None` on malformed XML or a non-`<Project>` root.
pub fn parse_directory_packages_props(content: &str) -> Option<Value> {
    let doc = Document::parse(content).ok()?;
    let root = doc.root_element();
    if root.tag_name().name() != "Project" {
        return None;
    }
    Some(json!({
        "cpm_enabled": extract_cpm_enabled(root),
        "packages": extract_package_versions(root),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpm_file() {
        let src = r#"<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageVersion Include="Serilog"><Version>3.1.1</Version></PackageVersion>
    <GlobalPackageReference Include="Nerdbank.GitVersioning" Version="3.6.133" />
    <PackageVersion Include="PropDep" Version="$(SomeVersion)" />
    <PackageVersion Include="newtonsoft.json" Version="13.0.4" />
  </ItemGroup>
</Project>"#;
        let cpm = parse_directory_packages_props(src).unwrap();
        assert_eq!(cpm["cpm_enabled"], true);
        let pkgs = cpm["packages"].as_array().unwrap();
        // Newtonsoft.Json deduped (case-insensitive, last wins) -> 13.0.4; PropDep skipped.
        let nj = pkgs.iter().find(|p| p["name"] == "newtonsoft.json").unwrap();
        assert_eq!(nj["version"], "13.0.4");
        let serilog = pkgs.iter().find(|p| p["name"] == "Serilog").unwrap();
        assert_eq!(serilog["version"], "3.1.1"); // child element
        let gv = pkgs.iter().find(|p| p["name"] == "Nerdbank.GitVersioning").unwrap();
        assert_eq!(gv["is_global"], true);
        assert!(pkgs.iter().all(|p| p["name"] != "PropDep")); // $() property skipped
        assert_eq!(pkgs.len(), 3);
    }

    #[test]
    fn cpm_disabled_and_non_project() {
        let src = "<Project><PropertyGroup><ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally></PropertyGroup></Project>";
        assert_eq!(parse_directory_packages_props(src).unwrap()["cpm_enabled"], false);
        assert!(parse_directory_packages_props("<NotProject/>").is_none());
    }
}
