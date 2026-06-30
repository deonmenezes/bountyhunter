//! docker-compose parser — Rust port of `packages/sca/parsers/compose.py`.
//! Extracts OCI container images from a compose file's `services` map. Takes
//! already-read content. (The fragment detection in the Python parser only
//! changes log level, not output, so it's omitted.)

use serde_json::Value;

use crate::models::{Confidence, Dependency, PinStyle};

const ECOSYSTEM: &str = "OCI";
const PURL_TYPE: &str = "oci";

/// Minimal Python `repr()` of a string for the confidence reason
/// (`{service_name!r}`): single-quoted, switching to double quotes when the
/// value contains a single but no double quote; escapes `\\ ' " \n \r \t`.
fn py_repr(s: &str) -> String {
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

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

fn build_dep(service_name: &str, service: &Value, declared_in: &str) -> Option<Dependency> {
    if service_name.is_empty() {
        return None;
    }
    let obj = service.as_object()?;
    let image = obj.get("image").and_then(Value::as_str)?.trim();
    if image.is_empty() {
        return None;
    }
    let (name, version) = split_image_ref(image);
    if name.is_empty() {
        return None;
    }
    let mut purl = format!("pkg:{PURL_TYPE}/{name}");
    if let Some(v) = &version {
        purl.push('@');
        purl.push_str(v);
    }
    let reason = format!("docker-compose service {} pinned to {}", py_repr(service_name), image);
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
        parser_confidence: Confidence::new("high", &reason),
        declared_license: None,
        commented_out: false,
        source_kind: "compose".to_string(),
        source_extra: Some(serde_json::json!({"service": service_name, "image_ref": image})),
    })
}

/// Parse a docker-compose file (`parse`): one Dependency per service `image`.
pub fn parse(content: &str, declared_in: &str) -> Vec<Dependency> {
    let Ok(data) = serde_yaml::from_str::<Value>(content) else { return Vec::new() };
    let Some(services) = data.get("services").and_then(Value::as_object) else { return Vec::new() };
    let mut out = Vec::new();
    for (service_name, service) in services {
        if let Some(d) = build_dep(service_name, service, declared_in) {
            out.push(d);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_images() {
        let src = "version: '3'\nservices:\n  web:\n    image: nginx:1.25\n  db:\n    image: postgres\n  cache:\n    image: ghcr.io/org/redis:7.2\n  pinned:\n    image: alpine@sha256:abcdef\n  reg:\n    image: localhost:5000/myimg:dev\n  nobuild:\n    build: .\n";
        let deps = parse(src, "docker-compose.yml");
        let by = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("nginx").version.as_deref(), Some("1.25"));
        assert_eq!(by("nginx").pin_style, PinStyle::Exact);
        assert_eq!(by("postgres").pin_style, PinStyle::Wildcard); // no tag
        assert_eq!(by("ghcr.io/org/redis").version.as_deref(), Some("7.2"));
        assert_eq!(by("alpine").version.as_deref(), Some("sha256:abcdef")); // digest
        // registry port not confused for a tag.
        assert_eq!(by("localhost:5000/myimg").version.as_deref(), Some("dev"));
        // service without image skipped.
        assert_eq!(deps.len(), 5);
    }
}
