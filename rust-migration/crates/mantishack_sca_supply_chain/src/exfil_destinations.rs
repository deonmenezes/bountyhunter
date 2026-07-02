//! Exfil-destination detector — Rust port of the pure core of
//! `packages/sca/supply_chain/exfil_destinations.py`.
//!
//! Scans source bytes for URLs and matches them against the embedded
//! `data/exfil_destinations.json` rule set (host-suffix / TLD / regex-on-URL).
//! The filesystem walk (`scan_target`, `_walk_source_files`, `_project_host_dep`)
//! stays call-site in Python and drives [`scan_content`] per file.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use serde_json::Value;

const EXFIL_JSON: &str = include_str!("../../../../packages/sca/data/exfil_destinations.json");

/// One exfil-destination match (the pure part of `ExfilFinding`).
#[derive(Clone, Debug, PartialEq)]
pub struct ExfilMatch {
    pub category: String,
    pub url: String,
    pub host: String,
    pub line: usize,
    pub severity: String,
    pub reason: String,
    /// `true` when a regex rule matched (Python uses `high` confidence then).
    pub high_confidence: bool,
}

struct Rule {
    category: String,
    severity: String,
    reason: String,
    host_suffix: Option<String>,
    pattern: Option<Regex>,
    tld: Option<String>,
}

fn rules() -> &'static Vec<Rule> {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut out = Vec::new();
        let Ok(data) = serde_json::from_str::<Value>(EXFIL_JSON) else { return out };
        let Some(entries) = data.get("entries").and_then(Value::as_array) else { return out };
        for entry in entries {
            let Some(entry) = entry.as_object() else { continue };
            let s = |k: &str, dflt: &str| {
                entry.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()).unwrap_or(dflt).to_string()
            };
            let severity = s("severity", "medium");
            let reason = s("reason", "matches known-bad pattern");
            let category = s("category", "unspecified");
            let pattern = match entry.get("pattern").and_then(Value::as_str) {
                Some(raw) => match Regex::new(raw) {
                    Ok(re) => Some(re),
                    Err(_) => continue, // bad pattern -> skip this rule
                },
                None => None,
            };
            let host_suffix = entry.get("host").and_then(Value::as_str).map(str::to_string);
            let tld = entry.get("tld").and_then(Value::as_str).map(str::to_string);
            if pattern.is_none() && host_suffix.is_none() && tld.is_none() {
                continue;
            }
            out.push(Rule { category, severity, reason, host_suffix, pattern, tld });
        }
        out
    })
}

fn url_re() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| {
        BytesRegex::new(r#"\bhttps?://(?P<host>[A-Za-z0-9.\-]+)(?::\d+)?(?P<rest>[^\s'"<>`)\]]*)"#)
            .unwrap()
    })
}

/// Whether a URL/host matches a rule (`_matches_rule`).
fn matches_rule(rule: &Rule, url: &str, host: &str) -> bool {
    if let Some(tld) = &rule.tld {
        if host.ends_with(&format!(".{}", tld.to_lowercase())) {
            return true;
        }
    }
    if let Some(suffix) = &rule.host_suffix {
        let suffix = suffix.to_lowercase();
        if host == suffix || host.ends_with(&format!(".{suffix}")) {
            return true;
        }
    }
    if let Some(pattern) = &rule.pattern {
        if pattern.is_match(url) {
            // raw_ip matches every IPv4; exclude non-WAN-routable addresses.
            if rule.category == "raw_ip" && is_non_routable_ipv4(host) {
                return false;
            }
            return true;
        }
    }
    false
}

/// Parse a strict dotted-quad IPv4 (rejecting leading zeros, as Python's
/// `ipaddress` does on 3.9+).
fn parse_ipv4(host: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || (p.len() > 1 && p.starts_with('0')) || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        octets[i] = p.parse::<u16>().ok().filter(|&v| v <= 255)? as u8;
    }
    Some(octets)
}

/// True if `host` is a non-WAN-routable IPv4 (loopback / link-local / RFC 1918)
/// (`_is_non_routable_ipv4`).
pub fn is_non_routable_ipv4(host: &str) -> bool {
    let Some(o) = parse_ipv4(host) else { return false };
    if o[0] == 127 {
        return true; // loopback 127.0.0.0/8
    }
    if o[0] == 169 && o[1] == 254 {
        return true; // link-local 169.254.0.0/16
    }
    o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
}

/// Scan already-read source `content` for exfil-destination URLs (the pure body
/// of `_scan_file`; per-file `(category, host)` dedup, fs/Manifest stay Python).
pub fn scan_content(content: &[u8]) -> Vec<ExfilMatch> {
    let mut out = Vec::new();
    if content.is_empty() {
        return out;
    }
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for caps in url_re().captures_iter(content) {
        let whole = caps.get(0).unwrap();
        let url = String::from_utf8_lossy(whole.as_bytes()).into_owned();
        let host = caps
            .name("host")
            .map(|m| String::from_utf8_lossy(m.as_bytes()).to_lowercase())
            .unwrap_or_default();
        for rule in rules() {
            if !matches_rule(rule, &url, &host) {
                continue;
            }
            let key = (rule.category.clone(), host.clone());
            if !seen.insert(key) {
                continue;
            }
            let line = content[..whole.start()].iter().filter(|&&b| b == b'\n').count() + 1;
            out.push(ExfilMatch {
                category: rule.category.clone(),
                url: url.clone(),
                host: host.clone(),
                line,
                severity: rule.severity.clone(),
                reason: rule.reason.clone(),
                high_confidence: rule.pattern.is_some(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_routable_ipv4() {
        for (h, want) in [
            ("127.0.0.1", true), ("10.1.2.3", true), ("172.16.0.1", true), ("172.32.0.1", false),
            ("192.168.1.1", true), ("169.254.1.1", true), ("8.8.8.8", false), ("example.com", false),
            ("1.2.3", false), ("256.1.1.1", false), ("192.168.001.1", false), ("0.0.0.0", false),
        ] {
            assert_eq!(is_non_routable_ipv4(h), want, "{h}");
        }
    }

    #[test]
    fn scan_matches() {
        let txt = b"a https://discord.com/api/webhooks/123/abc\nb http://8.8.8.8/x\nc http://127.0.0.1/y\nd https://api.telegram.org/bot123:xyz/z\n";
        let got = scan_content(txt);
        assert_eq!(got.len(), 3);
        assert_eq!((got[0].category.as_str(), got[0].host.as_str(), got[0].line, got[0].severity.as_str(), got[0].high_confidence),
            ("discord_webhook", "discord.com", 1, "high", true));
        // Public raw IP flagged; loopback 127.0.0.1 filtered out.
        assert_eq!((got[1].category.as_str(), got[1].host.as_str(), got[1].line, got[1].severity.as_str()),
            ("raw_ip", "8.8.8.8", 2, "medium"));
        assert!(!got.iter().any(|m| m.host == "127.0.0.1"));
        assert_eq!((got[2].category.as_str(), got[2].host.as_str(), got[2].line), ("telegram_bot", "api.telegram.org", 4));
    }

    #[test]
    fn empty_and_no_match() {
        assert!(scan_content(b"").is_empty());
        assert!(scan_content(b"no urls here, just text\n").is_empty());
        assert!(rules().len() >= 20);
    }
}
