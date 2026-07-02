//! License SPDX extraction — Rust port of the self-contained SPDX helpers in
//! `packages/sca/license.py`. The policy engine (`evaluate`/`_classify`) needs
//! the LicensePolicy + LicenseFinding models, and the registry `_fetch_*`
//! functions are HTTP; both stay Python. The pure SPDX-string extractors port
//! here.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

fn spdx_expr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[A-Za-z0-9.+\-]+(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9.+\-]+)+$").unwrap()
    })
}

/// True when `text` matches the SPDX compound-expression shape
/// (`_looks_like_spdx_expression`): `<id> (AND|OR|WITH) <id> …`.
pub fn looks_like_spdx_expression(text: &str) -> bool {
    spdx_expr_re().is_match(text.trim())
}

/// Map a PyPI `License ::` Trove classifier to an SPDX id (`_spdx_from_trove`);
/// `None` for unknown classifiers.
pub fn spdx_from_trove(classifier: &str) -> Option<&'static str> {
    let m: &[(&str, &str)] = &[
        ("License :: OSI Approved :: MIT License", "MIT"),
        ("License :: OSI Approved :: Apache Software License", "Apache-2.0"),
        ("License :: OSI Approved :: BSD License", "BSD-3-Clause"),
        ("License :: OSI Approved :: ISC License (ISCL)", "ISC"),
        ("License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)", "MPL-2.0"),
        ("License :: OSI Approved :: GNU General Public License v2 (GPLv2)", "GPL-2.0"),
        ("License :: OSI Approved :: GNU General Public License v3 (GPLv3)", "GPL-3.0"),
        ("License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)", "GPL-3.0-or-later"),
        ("License :: OSI Approved :: GNU Affero General Public License v3", "AGPL-3.0"),
        ("License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)", "AGPL-3.0-or-later"),
        ("License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)", "LGPL-2.0"),
        ("License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)", "LGPL-2.0-or-later"),
        ("License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)", "LGPL-3.0"),
        ("License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)", "LGPL-3.0-or-later"),
        ("License :: Public Domain", "Unlicense"),
        ("License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication", "CC0-1.0"),
    ];
    let key = classifier.trim();
    m.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

/// Extract an SPDX string from an npm `license`/`licenses` block
/// (`_spdx_from_npm_block`): a string, an object with `type`, or a list of
/// either.
pub fn spdx_from_npm_block(block: &Value) -> Option<String> {
    match block {
        Value::String(s) => {
            let t = s.trim();
            (!t.is_empty()).then(|| t.to_string())
        }
        Value::Object(o) => o.get("type").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string),
        Value::Array(a) => {
            for item in a {
                match item {
                    Value::Object(o) => {
                        if let Some(t) = o.get("type").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) {
                            return Some(t.to_string());
                        }
                    }
                    Value::String(s) => {
                        let t = s.trim();
                        if !t.is_empty() {
                            return Some(t.to_string());
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        _ => None,
    }
}

/// Extract the SPDX license from npm registry metadata (`_spdx_from_npm`).
/// Per-version `license`/`licenses` wins over the top-level.
pub fn spdx_from_npm(meta: &Value, version: Option<&str>) -> Option<String> {
    let meta = meta.as_object()?;
    if let Some(version) = version.filter(|v| !v.is_empty()) {
        if let Some(versions) = meta.get("versions").and_then(Value::as_object) {
            if let Some(v_meta) = versions.get(version).filter(|v| v.is_object()) {
                if let Some(s) = spdx_from_npm_block(v_meta.get("license").unwrap_or(&Value::Null)) {
                    return Some(s);
                }
                if let Some(s) = spdx_from_npm_block(v_meta.get("licenses").unwrap_or(&Value::Null)) {
                    return Some(s);
                }
            }
        }
    }
    if let Some(s) = spdx_from_npm_block(meta.get("license").unwrap_or(&Value::Null)) {
        return Some(s);
    }
    spdx_from_npm_block(meta.get("licenses").unwrap_or(&Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn spdx_expression_shape() {
        assert!(!looks_like_spdx_expression("MIT")); // no operator
        assert!(looks_like_spdx_expression("MIT OR Apache-2.0"));
        assert!(looks_like_spdx_expression("GPL-2.0 WITH Classpath-exception-2.0"));
        assert!(looks_like_spdx_expression("A AND B AND C"));
        assert!(!looks_like_spdx_expression("see LICENSE file"));
        assert!(!looks_like_spdx_expression("MIT ")); // trimmed, still no operator
    }

    #[test]
    fn trove_mapping() {
        assert_eq!(spdx_from_trove("License :: OSI Approved :: MIT License"), Some("MIT"));
        assert_eq!(spdx_from_trove("License :: Public Domain"), Some("Unlicense"));
        assert_eq!(spdx_from_trove("Unknown"), None);
    }

    #[test]
    fn npm_blocks_and_meta() {
        assert_eq!(spdx_from_npm_block(&json!("  MIT  ")).as_deref(), Some("MIT"));
        assert_eq!(spdx_from_npm_block(&json!({"type": "ISC", "url": "x"})).as_deref(), Some("ISC"));
        assert_eq!(spdx_from_npm_block(&json!([{"foo": 1}, {"type": "BSD-3-Clause"}])).as_deref(), Some("BSD-3-Clause"));
        assert_eq!(spdx_from_npm_block(&json!(["Apache-2.0"])).as_deref(), Some("Apache-2.0"));
        assert_eq!(spdx_from_npm_block(&json!({"url": "x"})), None);

        // Per-version override wins over top-level.
        assert_eq!(spdx_from_npm(&json!({"license": "MIT", "versions": {"1.0": {"license": "GPL-3.0"}}}), Some("1.0")).as_deref(), Some("GPL-3.0"));
        // Falls back to top-level when the version block has no license.
        assert_eq!(spdx_from_npm(&json!({"license": "MIT", "versions": {"1.0": {}}}), Some("1.0")).as_deref(), Some("MIT"));
        // Legacy top-level `licenses` list.
        assert_eq!(spdx_from_npm(&json!({"licenses": [{"type": "BSD-2-Clause"}]}), None).as_deref(), Some("BSD-2-Clause"));
    }
}
