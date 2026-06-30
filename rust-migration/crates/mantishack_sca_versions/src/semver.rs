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

// ---------------------------------------------------------------------------
// Range bounds — `(floor, ceiling)` for an npm/Cargo semver range.
// Port of `bounds` + helpers in packages/sca/versions/semver.py.
// ---------------------------------------------------------------------------

/// `(major, minor, patch, ncomp)` from a possibly-partial version, or `None`
/// for a bare wildcard / non-numeric (`_loose_components`).
fn loose_components(operand: &str) -> Option<(i64, i64, i64, i64)> {
    let trimmed = operand.trim().trim_start_matches('v');
    let core = trimmed.split(['-', '+']).next().unwrap_or("");
    let mut nums: Vec<i64> = Vec::new();
    for part in core.split('.') {
        if matches!(part, "x" | "X" | "*" | "") {
            break;
        }
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        nums.push(part.parse().ok()?);
    }
    if nums.is_empty() {
        return None;
    }
    Some((nums[0], *nums.get(1).unwrap_or(&0), *nums.get(2).unwrap_or(&0), nums.len() as i64))
}

fn join_components(c: (i64, i64, i64, i64)) -> String {
    format!("{}.{}.{}", c.0, c.1, c.2)
}

fn caret_ceiling(c: (i64, i64, i64, i64)) -> String {
    let (major, minor, patch, ncomp) = c;
    if major > 0 || ncomp == 1 {
        format!("{}.0.0", major + 1)
    } else if minor > 0 || ncomp == 2 {
        format!("0.{}.0", minor + 1)
    } else {
        format!("0.0.{}", patch + 1)
    }
}

fn tilde_ceiling(c: (i64, i64, i64, i64)) -> String {
    let (major, minor, _patch, ncomp) = c;
    if ncomp >= 2 {
        format!("{}.{}.0", major, minor + 1)
    } else {
        format!("{}.0.0", major + 1)
    }
}

fn split_op(tok: &str) -> (&str, &str) {
    for op in [">=", "<=", ">", "<", "=", "^", "~"] {
        if let Some(rest) = tok.strip_prefix(op) {
            return (op, rest.trim());
        }
    }
    ("", tok.trim())
}

fn tightest(versions: &[String], want_max: bool) -> String {
    let mut best = versions[0].clone();
    for v in &versions[1..] {
        let c = compare(v, &best).unwrap_or(0);
        if (want_max && c > 0) || (!want_max && c < 0) {
            best = v.clone();
        }
    }
    best
}

/// Best-effort `(floor, ceiling)` for an npm/Cargo semver range (`bounds`).
/// `(None, None)` for OR ranges, wildcards, or fully-specified exact pins.
pub fn bounds(spec: &str) -> (Option<String>, Option<String>) {
    let spec = spec.trim();
    if spec.is_empty() || spec.contains("||") {
        return (None, None);
    }
    if spec.contains(" - ") {
        let first = spec.split(" - ").next().unwrap_or("");
        return (loose_components(first).map(join_components), None);
    }

    let mut lowers: Vec<String> = Vec::new();
    let mut uppers: Vec<String> = Vec::new();
    for tok in spec.split_whitespace() {
        let (op, operand) = split_op(tok);
        if operand.is_empty() || matches!(operand, "*" | "x" | "X") {
            continue;
        }
        match op {
            "^" => {
                if let Some(c) = loose_components(operand) {
                    lowers.push(join_components(c));
                    uppers.push(caret_ceiling(c));
                }
            }
            "~" => {
                if let Some(c) = loose_components(operand) {
                    lowers.push(join_components(c));
                    uppers.push(tilde_ceiling(c));
                }
            }
            ">=" | ">" => {
                if let Some(c) = loose_components(operand) {
                    lowers.push(join_components(c));
                }
            }
            "<" | "<=" => {
                if let Some(c) = loose_components(operand) {
                    uppers.push(join_components(c));
                }
            }
            _ => {
                let Some(c) = loose_components(operand) else { continue };
                if c.3 >= 3 && !operand.contains(['x', 'X', '*']) {
                    continue; // fully-specified exact pin: no corridor
                }
                lowers.push(join_components(c));
                uppers.push(if c.3 == 1 {
                    format!("{}.0.0", c.0 + 1)
                } else {
                    format!("{}.{}.0", c.0, c.1 + 1)
                });
            }
        }
    }
    let floor = (!lowers.is_empty()).then(|| tightest(&lowers, true));
    let ceiling = (!uppers.is_empty()).then(|| tightest(&uppers, false));
    (floor, ceiling)
}

#[cfg(test)]
mod bounds_tests {
    use super::bounds;

    // Golden vectors: every expected output was produced by running the Python
    // oracle `packages/sca/versions/semver.py::bounds` on the same spec.
    fn b(spec: &str) -> (Option<String>, Option<String>) {
        bounds(spec)
    }
    fn pair(lo: Option<&str>, hi: Option<&str>) -> (Option<String>, Option<String>) {
        (lo.map(Into::into), hi.map(Into::into))
    }

    #[test]
    fn semver_bounds() {
        assert_eq!(b("^1.2.3"), pair(Some("1.2.3"), Some("2.0.0")));
        assert_eq!(b("^0.2.3"), pair(Some("0.2.3"), Some("0.3.0")));
        assert_eq!(b("~1.2.3"), pair(Some("1.2.3"), Some("1.3.0")));
        assert_eq!(b(">=1.0.0 <2.0.0"), pair(Some("1.0.0"), Some("2.0.0")));
        assert_eq!(b("2.7.0"), pair(None, None)); // exact pin -> no corridor
        assert_eq!(b("2.x"), pair(Some("2.0.0"), Some("3.0.0")));
        assert_eq!(b("^1.0 || ^2.0"), pair(None, None)); // OR
        assert_eq!(b("1.0.0 - 2.0.0"), pair(Some("1.0.0"), None));
        assert_eq!(b("*"), pair(None, None));
    }

    #[test]
    fn semver_bounds_edge_cases() {
        // Partial carets/tildes default trailing components to 0.
        assert_eq!(b("^1"), pair(Some("1.0.0"), Some("2.0.0")));
        assert_eq!(b("~1"), pair(Some("1.0.0"), Some("2.0.0")));
        assert_eq!(b("^0.0.3"), pair(Some("0.0.3"), Some("0.0.4")));
        // `=`-prefixed fully-specified pin contributes no corridor.
        assert_eq!(b("=2.7.0"), pair(None, None));
        // Open comparators yield a single bound.
        assert_eq!(b(">1.0.0"), pair(Some("1.0.0"), None));
        assert_eq!(b("<=3.0.0"), pair(None, Some("3.0.0")));
        // Bare partial version is an x-range corridor.
        assert_eq!(b("1.2"), pair(Some("1.2.0"), Some("1.3.0")));
        // A `v`-prefixed exact pin is still a pin (no corridor).
        assert_eq!(b("v2.3.4"), pair(None, None));
        // Whitespace-only / empty -> no corridor.
        assert_eq!(b("  "), pair(None, None));
        // Multiple comparators: tightest floor (max) and ceiling (min).
        assert_eq!(b(">=1.0.0 <2.0.0 <1.5.0"), pair(Some("1.0.0"), Some("1.5.0")));
        assert_eq!(b("^1.2.3 ^1.5.0"), pair(Some("1.5.0"), Some("2.0.0")));
    }
}
