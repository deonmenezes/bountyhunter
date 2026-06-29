/// Semver comparator — npm, Cargo, Go.
/// Faithfully ports packages/sca/versions/semver.py.
use std::cmp::Ordering;

/// Parse a semver string into (major, minor, patch, pre_identifiers).
/// Tolerates leading 'v', missing minor/patch (default 0), build metadata dropped.
pub fn parse(version: &str) -> Result<(u64, u64, u64, Option<Vec<String>>), String> {
    let s = version.trim().trim_start_matches('v');
    // Split off build metadata
    let s = s.splitn(2, '+').next().unwrap_or(s);
    // Split pre-release
    let (base, pre) = if let Some(idx) = s.find('-') {
        (&s[..idx], Some(&s[idx + 1..]))
    } else {
        (s, None)
    };
    let parts: Vec<&str> = base.split('.').collect();
    let major = parts.first().and_then(|p| p.parse::<u64>().ok())
        .ok_or_else(|| format!("not a semver version: {:?}", version))?;
    let minor = parts.get(1).and_then(|p| p.parse::<u64>().ok()).unwrap_or(0);
    let patch = parts.get(2).and_then(|p| p.parse::<u64>().ok()).unwrap_or(0);
    // Validate the base is purely numeric parts
    for p in &parts {
        if !p.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("not a semver version: {:?}", version));
        }
    }
    let pre_ids = pre.map(|p| p.split('.').map(|s| s.to_string()).collect());
    Ok((major, minor, patch, pre_ids))
}

fn compare_identifier(a: &str, b: &str) -> Ordering {
    let a_num = a.chars().all(|c| c.is_ascii_digit());
    let b_num = b.chars().all(|c| c.is_ascii_digit());
    match (a_num, b_num) {
        (true, true) => {
            let ai: u64 = a.parse().unwrap_or(0);
            let bi: u64 = b.parse().unwrap_or(0);
            ai.cmp(&bi)
        }
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => a.cmp(b),
    }
}

pub fn compare(a: &str, b: &str) -> Result<i32, String> {
    if a == b {
        return Ok(0);
    }
    let pa = parse(a)?;
    let pb = parse(b)?;
    // Compare major.minor.patch
    for (x, y) in [pa.0, pa.1, pa.2].iter().zip([pb.0, pb.1, pb.2].iter()) {
        match x.cmp(y) {
            Ordering::Less => return Ok(-1),
            Ordering::Greater => return Ok(1),
            Ordering::Equal => {}
        }
    }
    // Pre-release ordering
    match (&pa.3, &pb.3) {
        (None, None) => Ok(0),
        (None, Some(_)) => Ok(1),   // release > pre
        (Some(_), None) => Ok(-1),  // pre < release
        (Some(a_pre), Some(b_pre)) => {
            for (ai, bi) in a_pre.iter().zip(b_pre.iter()) {
                match compare_identifier(ai, bi) {
                    Ordering::Less => return Ok(-1),
                    Ordering::Greater => return Ok(1),
                    Ordering::Equal => {}
                }
            }
            match a_pre.len().cmp(&b_pre.len()) {
                Ordering::Less => Ok(-1),
                Ordering::Greater => Ok(1),
                Ordering::Equal => Ok(0),
            }
        }
    }
}
