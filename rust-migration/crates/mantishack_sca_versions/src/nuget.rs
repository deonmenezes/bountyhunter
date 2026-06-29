/// NuGet version comparator (SemVer 2.0 + 4-part legacy + quirks).
/// Faithfully ports packages/sca/versions/nuget.py.

fn split(version: &str) -> (Vec<u64>, Vec<String>) {
    let s = version.trim().trim_start_matches('v');
    let s = s.splitn(2, '+').next().unwrap_or(s); // drop build metadata
    let (base, pre) = if let Some(idx) = s.find('-') {
        (&s[..idx], &s[idx + 1..])
    } else {
        (s, "")
    };
    let nums: Vec<u64> = base.split('.').map(|p| p.parse::<u64>().unwrap_or(0)).collect();
    let pre_segs: Vec<String> = if pre.is_empty() {
        vec![]
    } else {
        pre.split('.').map(|p| p.to_lowercase()).collect()
    };
    (nums, pre_segs)
}

fn cmp_prerelease(a: &[String], b: &[String]) -> i32 {
    for (sa, sb) in a.iter().zip(b.iter()) {
        let a_num = sa.chars().all(|c| c.is_ascii_digit());
        let b_num = sb.chars().all(|c| c.is_ascii_digit());
        if a_num && b_num {
            let ia: u64 = sa.parse().unwrap_or(0);
            let ib: u64 = sb.parse().unwrap_or(0);
            if ia != ib {
                return if ia < ib { -1 } else { 1 };
            }
        } else if a_num != b_num {
            return if a_num { -1 } else { 1 };
        } else if sa != sb {
            return if sa < sb { -1 } else { 1 };
        }
    }
    match a.len().cmp(&b.len()) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Equal => 0,
    }
}

pub fn compare(a: &str, b: &str) -> Result<i32, String> {
    let (mut pa, qa) = split(a);
    let (mut pb, qb) = split(b);
    let max_len = pa.len().max(pb.len());
    while pa.len() < max_len { pa.push(0); }
    while pb.len() < max_len { pb.push(0); }
    for (x, y) in pa.iter().zip(pb.iter()) {
        if x != y {
            return Ok(if x < y { -1 } else { 1 });
        }
    }
    match (qa.is_empty(), qb.is_empty()) {
        (true, true) => Ok(0),
        (true, false) => Ok(1),
        (false, true) => Ok(-1),
        (false, false) => Ok(cmp_prerelease(&qa, &qb)),
    }
}
