//! Typosquat-domain detector — Rust port of the pure core of
//! `packages/sca/supply_chain/typosquat_domain.py`.
//!
//! Extracts URL hosts from source text and flags near-miss hostnames against
//! the embedded `data/popular_domains.json` list. The filesystem walk
//! (`scan_target`, `_walk_sources`, `_stub_dep`) stays call-site in Python and
//! drives [`find_suspect_hosts`] on each file's already-read content.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

const MAX_DISTANCE: usize = 2;

const POPULAR_DOMAINS_JSON: &str =
    include_str!("../../../../packages/sca/data/popular_domains.json");

const SKIP_HOSTS: &[&str] = &["localhost", "127.0.0.1", "0.0.0.0", "::1"];

/// One near-miss host occurrence (the pure part of `TyposquatDomainFinding`).
#[derive(Clone, Debug, PartialEq)]
pub struct SuspectHost {
    pub host: String,
    pub line: usize,
    pub distance: usize,
    pub nearest_popular: String,
}

struct PopularDomains {
    list: Vec<String>,
    set: HashSet<String>,
}

fn popular_domains() -> &'static PopularDomains {
    static P: OnceLock<PopularDomains> = OnceLock::new();
    P.get_or_init(|| {
        let mut list = Vec::new();
        let mut set = HashSet::new();
        if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str(POPULAR_DOMAINS_JSON) {
            for d in arr {
                // `{str(d).lower() for d in data}` — stringify + lowercase, deduped.
                let s = match d {
                    serde_json::Value::String(s) => s.to_lowercase(),
                    other => other.to_string().to_lowercase(),
                };
                if set.insert(s.clone()) {
                    list.push(s);
                }
            }
        }
        PopularDomains { list, set }
    })
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"https?://(?P<host>[A-Za-z0-9._\-]+)").unwrap())
}

/// Yield `(host_lowercased, line_number)` for every URL in `text` (`_hosts_in`).
pub fn hosts_in(text: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let mut last_pos = 0usize;
    let mut last_line = 1usize;
    for caps in url_re().captures_iter(text) {
        let start = caps.get(0).unwrap().start();
        last_line += text[last_pos..start].matches('\n').count();
        last_pos = start;
        out.push((caps.name("host").unwrap().as_str().to_lowercase(), last_line));
    }
    out
}

/// Full-matrix Damerau-Levenshtein for short hostnames (`_damerau_levenshtein`).
/// Returns `cap + 1` when the distance exceeds `cap`.
pub fn damerau_levenshtein_domain(a: &[char], b: &[char], cap: usize) -> usize {
    if a == b {
        return 0;
    }
    let (la, lb) = (a.len(), b.len());
    if (la as isize - lb as isize).unsigned_abs() > cap {
        return cap + 1;
    }
    let mut dp = vec![vec![0usize; lb + 1]; la + 1];
    for (i, row) in dp.iter_mut().enumerate() {
        row[0] = i;
    }
    for j in 0..=lb {
        dp[0][j] = j;
    }
    for i in 1..=la {
        for j in 1..=lb {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1).min(dp[i][j - 1] + 1).min(dp[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                dp[i][j] = dp[i][j].min(dp[i - 2][j - 2] + 1);
            }
        }
        if *dp[i].iter().min().unwrap() > cap {
            return cap + 1;
        }
    }
    dp[la][lb]
}

fn dl(a: &str, b: &str, cap: usize) -> usize {
    let ac: Vec<char> = a.chars().collect();
    let bc: Vec<char> = b.chars().collect();
    damerau_levenshtein_domain(&ac, &bc, cap)
}

/// Heuristic "same registrable domain" without a public-suffix list
/// (`_same_registrable_domain`): both have ≥3 labels and share all-but-leftmost.
pub fn same_registrable_domain(a: &str, b: &str) -> bool {
    let a_parts: Vec<&str> = a.split('.').collect();
    let b_parts: Vec<&str> = b.split('.').collect();
    if a_parts.len() != b_parts.len() {
        return false;
    }
    if a_parts.len() < 3 {
        return false;
    }
    a_parts[1..] == b_parts[1..]
}

/// Nearest popular domain to `host` within `MAX_DISTANCE`, or `None`
/// (`_nearest_popular`). Exact matches (distance 0) and in-family subdomain
/// variations are skipped.
pub fn nearest_popular(host: &str) -> Option<(usize, String)> {
    let mut best: Option<(usize, String)> = None;
    for pop in &popular_domains().list {
        let d = dl(host, pop, MAX_DISTANCE + 1);
        if d > MAX_DISTANCE || d == 0 {
            continue;
        }
        if same_registrable_domain(host, pop) {
            continue;
        }
        if best.as_ref().map_or(true, |(bd, _)| d < *bd) {
            best = Some((d, pop.clone()));
        }
    }
    best
}

/// Scan already-read source `text` for near-miss typosquat-domain hosts (the
/// pure body of `scan_target`'s per-file loop; fs walk + finding assembly stay
/// call-site).
pub fn find_suspect_hosts(text: &str) -> Vec<SuspectHost> {
    let skip: HashSet<&str> = SKIP_HOSTS.iter().copied().collect();
    let popular = popular_domains();
    let mut out = Vec::new();
    for (host, line) in hosts_in(text) {
        if skip.contains(host.as_str()) || !host.contains('.') || popular.set.contains(&host) {
            continue;
        }
        if let Some((distance, nearest)) = nearest_popular(&host) {
            out.push(SuspectHost { host, line, distance, nearest_popular: nearest });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_dl() {
        assert_eq!(dl("github.com", "gihub.com", 3), 1);
        assert_eq!(dl("github.com", "gtihub.com", 3), 1);
        assert_eq!(dl("github.com", "github.com", 3), 0);
        assert_eq!(dl("abc", "abcd", 3), 1);
        assert_eq!(dl("aaaaaa", "b", 3), 4); // exceeds cap -> cap+1
        assert_eq!(dl("pypi.org", "pypitorg", 3), 1);
    }

    #[test]
    fn registrable_domain() {
        assert!(same_registrable_domain("registry-2.docker.io", "registry-1.docker.io"));
        assert!(!same_registrable_domain("goagle.com", "google.com"));
        assert!(same_registrable_domain("api.shop.example.com", "cdn.shop.example.com"));
        assert!(!same_registrable_domain("evil.com", "evil.io"));
    }

    #[test]
    fn host_extraction_and_lines() {
        let got = hosts_in("see http://github.com/x\nand\nhttps://Evil.COM/y no more");
        assert_eq!(got, vec![("github.com".to_string(), 1), ("evil.com".to_string(), 3)]);
    }

    #[test]
    fn nearest_and_scan() {
        // Unambiguous distance-1 near-miss.
        assert_eq!(nearest_popular("gihub.com"), Some((1, "github.com".to_string())));
        assert_eq!(nearest_popular("gtihub.com"), Some((1, "github.com".to_string())));
        assert_eq!(nearest_popular("zzzz.qqqq"), None);

        let scan = find_suspect_hosts("x http://gihub.com/a\n# http://github.com ok\nhttp://localhost/z\n");
        assert_eq!(scan.len(), 1);
        assert_eq!((scan[0].host.as_str(), scan[0].line, scan[0].distance, scan[0].nearest_popular.as_str()),
            ("gihub.com", 1, 1, "github.com"));
    }
}
