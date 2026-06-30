//! GitLab CI parser — Rust port of `packages/sca/parsers/gitlab_ci.py`.
//! Extracts OCI images from `image:`/`services:` at the top level and per job.
//! Takes already-read content.

use serde_json::{json, Value};

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "OCI";
const PURL_TYPE: &str = "oci";

const RESERVED_KEYS: &[&str] = &[
    "image", "services", "variables", "stages", "default", "include",
    "before_script", "after_script", "workflow", "cache", "artifacts",
    "pages", "trigger",
];

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

fn extract_image(block: &Value, label: &str, refs: &mut Vec<(String, String)>) {
    let Some(obj) = block.as_object() else { return };
    match obj.get("image") {
        Some(Value::String(s)) if !s.trim().is_empty() => {
            refs.push((s.trim().to_string(), format!("{label} image")));
        }
        Some(image) if image.is_object() => {
            if let Some(name) = image.get("name").and_then(Value::as_str) {
                if !name.trim().is_empty() {
                    refs.push((name.trim().to_string(), format!("{label} image")));
                }
            }
        }
        _ => {}
    }
}

fn extract_services(block: &Value, label: &str, refs: &mut Vec<(String, String)>) {
    let Some(services) = block.get("services").and_then(Value::as_array) else { return };
    for entry in services {
        match entry {
            Value::String(s) if !s.trim().is_empty() => {
                refs.push((s.trim().to_string(), label.to_string()));
            }
            e if e.is_object() => {
                if let Some(name) = e.get("name").and_then(Value::as_str) {
                    if !name.trim().is_empty() {
                        refs.push((name.trim().to_string(), label.to_string()));
                    }
                }
            }
            _ => {}
        }
    }
}

fn build_dep(image_ref: &str, context: &str, declared_in: &str) -> Option<Dependency> {
    let (name, version) = split_image_ref(image_ref);
    if name.is_empty() {
        return None;
    }
    let mut purl = format!("pkg:{PURL_TYPE}/{name}");
    if let Some(v) = &version {
        purl.push('@');
        purl.push_str(v);
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
        parser_confidence: Confidence::new("high", &format!(".gitlab-ci.yml {context}: {image_ref}")),
        declared_license: None,
        commented_out: false,
        source_kind: "gitlab_ci".to_string(),
        source_extra: Some(json!({"context": context, "image_ref": image_ref})),
    })
}

/// Parse a `.gitlab-ci.yml` (`parse`): images from top-level + per-job blocks,
/// deduped by (image_ref, context).
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_yaml::from_str::<Value>(content) else { return Vec::new() };
    let Some(obj) = data.as_object() else { return Vec::new() };

    let mut refs: Vec<(String, String)> = Vec::new();
    extract_image(&data, "top-level", &mut refs);
    extract_services(&data, "top-level services", &mut refs);

    for (job_name, job) in obj {
        if RESERVED_KEYS.contains(&job_name.as_str()) || !job.is_object() {
            continue;
        }
        extract_image(job, &format!("job {job_name}"), &mut refs);
        extract_services(job, &format!("job {job_name} services"), &mut refs);
    }

    let mut seen: Vec<(String, String)> = Vec::new();
    let mut out = Vec::new();
    for (image_ref, ctx) in refs {
        let key = (image_ref.clone(), ctx.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        if let Some(d) = build_dep(&image_ref, &ctx, declared_in) {
            out.push(d);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitlab_ci_images() {
        let src = "image: python:3.12\n\nservices:\n  - postgres:16\n  - name: redis:7\n\ntest:\n  image:\n    name: node:20\n  services:\n    - mysql:8\n  script: [\"make test\"]\n\nvariables:\n  FOO: bar\n";
        let deps = parse(src, ".gitlab-ci.yml");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("python").version.as_deref(), Some("3.12"));
        assert_eq!(by("postgres").version.as_deref(), Some("16"));
        assert_eq!(by("redis").version.as_deref(), Some("7")); // services dict form
        assert_eq!(by("node").source_extra.as_ref().unwrap()["context"], "job test image");
        assert_eq!(by("mysql").source_extra.as_ref().unwrap()["context"], "job test services");
        // variables (reserved) not treated as a job.
        assert!(deps.iter().all(|d| d.name != "bar"));
    }
}
