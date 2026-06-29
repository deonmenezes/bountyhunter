/// Debian (dpkg) version comparator.
/// Faithfully ports packages/sca/versions/debian.py — dpkg Policy §5.6.12.

fn split(version: &str) -> Result<(u64, String, String), String> {
    let v = version.trim();
    let (epoch, rest) = if let Some(colon_pos) = v.find(':') {
        let head = &v[..colon_pos];
        if !head.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("invalid Debian epoch in {:?}", version));
        }
        let epoch: u64 = head.parse().unwrap_or(0);
        (epoch, &v[colon_pos + 1..])
    } else {
        (0, v)
    };
    let (upstream, revision) = if let Some(dash_pos) = rest.rfind('-') {
        (&rest[..dash_pos], &rest[dash_pos + 1..])
    } else {
        (rest, "")
    };
    Ok((epoch, upstream.to_string(), revision.to_string()))
}

fn order(c: Option<char>) -> i32 {
    match c {
        None | Some('\0') => 0,
        Some(ch) if ch.is_ascii_digit() => 0,
        Some(ch) if ch.is_ascii_alphabetic() => ch as i32,
        Some('~') => -1,
        Some(ch) => ch as i32 + 256,
    }
}

fn verrevcmp(a: &str, b: &str) -> i32 {
    let a_bytes: Vec<char> = a.chars().collect();
    let b_bytes: Vec<char> = b.chars().collect();
    let mut ia = 0usize;
    let mut ib = 0usize;
    let la = a_bytes.len();
    let lb = b_bytes.len();

    while ia < la || ib < lb {
        // Non-digit run
        while (ia < la && !a_bytes[ia].is_ascii_digit())
            || (ib < lb && !b_bytes[ib].is_ascii_digit())
        {
            let oa = order(a_bytes.get(ia).copied());
            let ob = order(b_bytes.get(ib).copied());
            if oa != ob {
                return if oa < ob { -1 } else { 1 };
            }
            ia += 1;
            ib += 1;
        }
        // Strip leading zeros
        while ia < la && a_bytes[ia] == '0' { ia += 1; }
        while ib < lb && b_bytes[ib] == '0' { ib += 1; }
        // Compare digit runs
        let mut first_diff = 0i32;
        while ia < la && a_bytes[ia].is_ascii_digit()
            && ib < lb && b_bytes[ib].is_ascii_digit()
        {
            if first_diff == 0 {
                first_diff = a_bytes[ia] as i32 - b_bytes[ib] as i32;
            }
            ia += 1;
            ib += 1;
        }
        if ia < la && a_bytes[ia].is_ascii_digit() { return 1; }
        if ib < lb && b_bytes[ib].is_ascii_digit() { return -1; }
        if first_diff != 0 {
            return if first_diff < 0 { -1 } else { 1 };
        }
    }
    0
}

pub fn compare(a: &str, b: &str) -> Result<i32, String> {
    if a == b {
        return Ok(0);
    }
    let (ea, ua, ra) = split(a)?;
    let (eb, ub, rb) = split(b)?;
    if ea != eb {
        return Ok(if ea < eb { -1 } else { 1 });
    }
    let c = verrevcmp(&ua, &ub);
    if c != 0 {
        return Ok(c);
    }
    Ok(verrevcmp(&ra, &rb))
}
