//! Kubernetes manifest parser — Rust port of
//! `packages/sca/parsers/kubernetes.py`. Extracts OCI container images from
//! workload docs in a (possibly multi-document) YAML manifest. Takes
//! already-read content.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "OCI";
const PURL_TYPE: &str = "oci";

const WORKLOAD_KINDS: &[&str] = &[
    "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
    "ReplicationController", "Job", "CronJob",
];

/// OCI image-ref split (shared logic with compose/gitlab_ci).
fn split_image_ref(reference: &str) -> (String, Option<String>) {
    if reference.contains('@') {
        let (name, digest) = reference.rsplit_once('@').unwrap();
        return (name.to_string(), if digest.is_empty() { None } else { Some(digest.to_string()) });
    }
    let last_slash = reference.rfind('/');
    let rest = match last_slash {
        Some(i) => &reference[i + 1..],
        None => reference,
    };
    if rest.contains(':') {
        let prefix = match last_slash {
            Some(i) => &reference[..i + 1],
            None => "",
        };
        let (rest_name, tag) = rest.split_once(':').unwrap();
        return (format!("{prefix}{rest_name}"), if tag.is_empty() { None } else { Some(tag.to_string()) });
    }
    (reference.to_string(), None)
}

/// `(image_ref, kind_context, container_name)` for each container in `doc`.
fn extract_images(doc: &Value, kind: &str) -> Vec<(String, String, Option<String>)> {
    let mut out = Vec::new();
    let Some(spec) = doc.get("spec").and_then(Value::as_object) else { return out };
    // Higher-level workloads nest containers under template.spec.
    let template_spec = spec
        .get("template")
        .and_then(Value::as_object)
        .and_then(|t| t.get("spec"))
        .and_then(Value::as_object)
        .unwrap_or(spec);

    let workload_name = doc
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str);
    let label = match workload_name {
        Some(n) => format!("{kind}/{n}"),
        None => kind.to_string(),
    };

    for container_field in ["containers", "initContainers", "ephemeralContainers"] {
        let Some(containers) = template_spec.get(container_field).and_then(Value::as_array) else { continue };
        for container in containers {
            let Some(c) = container.as_object() else { continue };
            let Some(image) = c.get("image").and_then(Value::as_str) else { continue };
            let image = image.trim();
            if image.is_empty() {
                continue;
            }
            let cname = c.get("name").and_then(Value::as_str).map(str::to_string);
            out.push((image.to_string(), format!("{label} {container_field}"), cname));
        }
    }
    out
}

fn build_dep(image_ref: &str, kind_ctx: &str, container_name: Option<&str>, declared_in: &str) -> Option<Dependency> {
    let (name, version) = split_image_ref(image_ref);
    if name.is_empty() {
        return None;
    }
    let mut purl = format!("pkg:{PURL_TYPE}/{name}");
    if let Some(v) = &version {
        purl.push('@');
        purl.push_str(v);
    }
    let mut extra = json!({"context": kind_ctx, "image_ref": image_ref});
    if let Some(c) = container_name {
        extra["container"] = json!(c);
    }
    let pin_style = if version.is_some() { PinStyle::Exact } else { PinStyle::Wildcard };
    Some(Dependency {
        ecosystem: ECOSYSTEM.to_string(),
        name,
        version,
        declared_in: declared_in.to_string(),
        scope: "main".to_string(),
        is_lockfile: false,
        pin_style,
        direct: true,
        purl,
        parser_confidence: Confidence::new("high", &format!("k8s {kind_ctx}: {image_ref}")),
        declared_license: None,
        commented_out: false,
        source_kind: "k8s".to_string(),
        source_extra: Some(extra),
    })
}

/// Parse a Kubernetes manifest (`parse`): images from each workload doc. Any
/// malformed document fails the whole parse (matching `safe_load_all`).
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let mut documents = Vec::new();
    for de in serde_yaml::Deserializer::from_str(content) {
        match Value::deserialize(de) {
            Ok(v) => documents.push(v),
            Err(_) => return Vec::new(),
        }
    }
    let mut out = Vec::new();
    for doc in &documents {
        if !doc.is_object() {
            continue;
        }
        let Some(kind) = doc.get("kind").and_then(Value::as_str) else { continue };
        if !WORKLOAD_KINDS.contains(&kind) {
            continue;
        }
        for (image_ref, kind_ctx, container_name) in extract_images(doc, kind) {
            if let Some(d) = build_dep(&image_ref, &kind_ctx, container_name.as_deref(), declared_in) {
                out.push(d);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k8s_workloads() {
        let src = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      initContainers:\n        - name: init\n          image: busybox:1.36\n      containers:\n        - name: app\n          image: nginx:1.25\n        - name: side\n          image: ghcr.io/x/y@sha256:abc\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\n";
        let deps = parse(src, "deploy.yaml");
        assert_eq!(deps.len(), 3); // ConfigMap is not a workload
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("nginx").version.as_deref(), Some("1.25"));
        assert_eq!(by("busybox").source_extra.as_ref().unwrap()["context"], "Deployment/web initContainers");
        assert_eq!(by("ghcr.io/x/y").version.as_deref(), Some("sha256:abc"));
    }
}
