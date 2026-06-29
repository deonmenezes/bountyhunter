/// Composer (PHP/Packagist) version comparator.
/// Faithfully ports packages/sca/versions/composer.py.

fn stability_rank(s: &str) -> i32 {
    match s.to_lowercase().as_str() {
        "dev" => 0,
        "alpha" | "a" => 1,
        "beta" | "b" => 2,
        "rc" | "pre" => 3,
        "stable" | "release" | "" => 4,
        _ => 4,
    }
}

fn is_dev(v: &str) -> bool {
    v.trim().to_lowercase().starts_with("dev-")
}

fn split(version: &str) -> (Vec<u64>, i32, u64) {
    let s = version.trim();
    // Regex: ^(?P<base>v?\d[\d.]*)(?:[-.]?(?P<stab>alpha|beta|rc|pre|stable|release|dev|a|b)(?P<idx>\d*))?
    // Find base (digits and dots, with optional leading v)
    let s_stripped = s.trim_start_matches('v');
    let base_end = s_stripped.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(s_stripped.len());
    let base = &s_stripped[..base_end];
    let rest = &s_stripped[base_end..];

    let nums: Vec<u64> = base.split('.').filter_map(|p| p.parse::<u64>().ok()).collect();
    let nums = if nums.is_empty() { vec![0] } else { nums };

    // Parse optional stability suffix from rest
    let rest_lower = rest.trim_start_matches(|c| c == '-' || c == '.').to_lowercase();
    let stab_labels = ["alpha", "beta", "stable", "release", "pre", "rc", "dev", "a", "b"];
    // Sort longest first to avoid prefix collisions
    let mut stab_sorted = stab_labels.to_vec();
    stab_sorted.sort_by(|a, b| b.len().cmp(&a.len()));

    let mut rank = stability_rank("");
    let mut idx: u64 = 0;
    for label in &stab_sorted {
        if rest_lower.starts_with(label) {
            let after = &rest_lower[label.len()..];
            let digit_end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
            idx = after[..digit_end].parse().unwrap_or(0);
            rank = stability_rank(label);
            break;
        }
    }

    (nums, rank, idx)
}

pub fn compare(a: &str, b: &str) -> Result<i32, String> {
    let da = is_dev(a);
    let db = is_dev(b);
    match (da, db) {
        (true, true) => {
            // Lex sort branch names
            if a > b { Ok(1) } else if a < b { Ok(-1) } else { Ok(0) }
        }
        (true, false) => Ok(1),  // dev sorts after releases
        (false, true) => Ok(-1),
        (false, false) => {
            let (mut nums_a, stab_a, idx_a) = split(a);
            let (mut nums_b, stab_b, idx_b) = split(b);
            let max_len = nums_a.len().max(nums_b.len());
            while nums_a.len() < max_len { nums_a.push(0); }
            while nums_b.len() < max_len { nums_b.push(0); }
            for (x, y) in nums_a.iter().zip(nums_b.iter()) {
                if x != y {
                    return Ok(if x < y { -1 } else { 1 });
                }
            }
            if stab_a != stab_b {
                return Ok(if stab_a < stab_b { -1 } else { 1 });
            }
            if idx_a != idx_b {
                return Ok(if idx_a < idx_b { -1 } else { 1 });
            }
            Ok(0)
        }
    }
}
