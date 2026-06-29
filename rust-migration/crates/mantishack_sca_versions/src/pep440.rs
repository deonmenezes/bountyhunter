/// PEP 440 version comparator (Python/PyPI).
/// Faithfully ports packages/sca/versions/pep440.py — the fallback comparator.
use std::cmp::Ordering;
use regex::Regex;
use std::sync::OnceLock;

static RE: OnceLock<Regex> = OnceLock::new();

fn regex() -> &'static Regex {
    RE.get_or_init(|| {
        Regex::new(
            r"(?xi)
            ^
            (?P<release>\d+(?:\.\d+)*)
            (?:(?P<pre_l>a|b|c|rc|alpha|beta|pre)(?P<pre_n>\d+))?
            (?:\.post(?P<post>\d+))?
            (?:\.dev(?P<dev>\d+))?
            $"
        ).unwrap()
    })
}

#[derive(Debug, PartialEq, Eq)]
struct Pep440Version {
    release: Vec<u64>,
    pre: Option<(u8, u64)>, // (0=a,1=b,2=rc, n)
    post: Option<u64>,
    dev: Option<u64>,
}

fn normalise_pre_label(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "a" | "alpha" => 0,
        "b" | "beta" => 1,
        _ => 2, // c, rc, pre
    }
}

fn parse(v: &str) -> Result<Pep440Version, String> {
    let s = v.trim();
    let caps = regex().captures(s)
        .ok_or_else(|| format!("unparseable PEP 440 (fallback): {:?}", v))?;

    let release: Vec<u64> = caps["release"].split('.')
        .map(|p| p.parse::<u64>().unwrap_or(0))
        .collect();

    let pre = caps.name("pre_l").map(|l| {
        let ord = normalise_pre_label(l.as_str());
        let n: u64 = caps.name("pre_n")
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        (ord, n)
    });

    let post = caps.name("post").and_then(|m| m.as_str().parse::<u64>().ok());
    let dev = caps.name("dev").and_then(|m| m.as_str().parse::<u64>().ok());

    Ok(Pep440Version { release, pre, post, dev })
}

// Category: 0=dev-only, 1=pre+dev, 2=pre, 3=release, 4=post
fn category(v: &Pep440Version) -> u8 {
    match (&v.pre, &v.post, &v.dev) {
        (None, None, Some(_)) => 0,
        (Some(_), _, Some(_)) => 1,
        (Some(_), _, None) => 2,
        (_, Some(_), _) => 4,
        _ => 3,
    }
}

pub fn compare(a: &str, b: &str) -> Result<i32, String> {
    if a == b {
        return Ok(0);
    }
    let va = parse(a)?;
    let vb = parse(b)?;

    // Compare release component-wise, padded with zeros
    let max_len = va.release.len().max(vb.release.len());
    for idx in 0..max_len {
        let ra = va.release.get(idx).copied().unwrap_or(0);
        let rb = vb.release.get(idx).copied().unwrap_or(0);
        match ra.cmp(&rb) {
            Ordering::Less => return Ok(-1),
            Ordering::Greater => return Ok(1),
            Ordering::Equal => {}
        }
    }

    // Compare by category
    let ca = category(&va);
    let cb = category(&vb);
    if ca != cb {
        return Ok(if ca < cb { -1 } else { 1 });
    }

    // Same category — compare sub-keys
    fn sub_key(v: &Pep440Version) -> (i64, i64, i64, i64) {
        let pre_label = v.pre.as_ref().map(|(l, _)| *l as i64).unwrap_or(-1);
        let pre_n = v.pre.as_ref().map(|(_, n)| *n as i64).unwrap_or(-1);
        let post = v.post.map(|p| p as i64).unwrap_or(0);
        let dev = v.dev.map(|d| d as i64).unwrap_or(0);
        (pre_label, pre_n, post, dev)
    }
    let ka = sub_key(&va);
    let kb = sub_key(&vb);
    if ka == kb {
        return Ok(0);
    }
    Ok(if ka < kb { -1 } else { 1 })
}
