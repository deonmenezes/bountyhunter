/// RubyGems version comparator.
/// Faithfully ports packages/sca/versions/gem.py.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Num(u64),
    Str(String),
}

fn segments(version: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    for part in version.trim().split('.') {
        // Split on digit/alpha transitions like Ruby's Gem::Version
        let mut chars = part.chars().peekable();
        let mut current = String::new();
        let mut is_digit_run: Option<bool> = None;
        while let Some(c) = chars.next() {
            let is_digit = c.is_ascii_digit();
            match is_digit_run {
                None => {
                    is_digit_run = Some(is_digit);
                    current.push(c);
                }
                Some(was_digit) if was_digit == is_digit => {
                    current.push(c);
                }
                Some(_) => {
                    // Flush current
                    if let Some(true) = is_digit_run {
                        out.push(Segment::Num(current.parse().unwrap_or(0)));
                    } else {
                        out.push(Segment::Str(current.to_lowercase()));
                    }
                    current = c.to_string();
                    is_digit_run = Some(is_digit);
                }
            }
        }
        if !current.is_empty() {
            if let Some(true) = is_digit_run {
                out.push(Segment::Num(current.parse().unwrap_or(0)));
            } else {
                out.push(Segment::Str(current.to_lowercase()));
            }
        }
    }
    out
}

fn cmp_segment(x: &Segment, y: &Segment) -> i32 {
    match (x, y) {
        (Segment::Num(a), Segment::Num(b)) => {
            if a < b { -1 } else if a > b { 1 } else { 0 }
        }
        (Segment::Str(a), Segment::Str(b)) => {
            if a < b { -1 } else if a > b { 1 } else { 0 }
        }
        (Segment::Str(_), Segment::Num(_)) => -1, // string < int
        (Segment::Num(_), Segment::Str(_)) => 1,
    }
}

pub fn compare(a: &str, b: &str) -> Result<i32, String> {
    let mut sa = segments(a);
    let mut sb = segments(b);
    let max_len = sa.len().max(sb.len());
    while sa.len() < max_len { sa.push(Segment::Num(0)); }
    while sb.len() < max_len { sb.push(Segment::Num(0)); }
    for (x, y) in sa.iter().zip(sb.iter()) {
        let c = cmp_segment(x, y);
        if c != 0 { return Ok(c); }
    }
    Ok(0)
}
