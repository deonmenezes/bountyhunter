/// Maven version comparator.
/// Faithfully ports packages/sca/versions/maven.py.
use std::cmp::Ordering;

// Well-known qualifier ordering — same as Python source.
fn qualifier_order(q: &str) -> Option<i32> {
    match q {
        "alpha" | "a" => Some(-5),
        "beta" | "b" => Some(-4),
        "milestone" | "m" => Some(-3),
        "rc" | "cr" => Some(-2),
        "snapshot" => Some(-1),
        "" | "ga" | "final" | "release" => Some(0),
        "sp" => Some(1),
        _ => None,
    }
}

#[derive(Debug, Clone)]
enum Token {
    Int(i64),
    Str(String),
    Sep(char),
}

fn tokenise(version: &str) -> Vec<Token> {
    let s = version.trim().to_lowercase();
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut num = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    num.push(d);
                    chars.next();
                } else {
                    break;
                }
            }
            out.push(Token::Int(num.parse().unwrap_or(0)));
        } else if c.is_ascii_alphabetic() {
            let mut word = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_alphabetic() {
                    word.push(d);
                    chars.next();
                } else {
                    break;
                }
            }
            out.push(Token::Str(word));
        } else if c == '.' || c == '-' || c == '_' {
            out.push(Token::Sep(c));
            chars.next();
        } else {
            chars.next(); // skip unknown
        }
    }
    out
}

#[derive(Debug, Clone)]
enum Item {
    Int(i64),
    Str(String),
}

fn items(version: &str) -> Vec<Item> {
    tokenise(version).into_iter().filter_map(|t| match t {
        Token::Int(n) => Some(Item::Int(n)),
        Token::Str(s) => Some(Item::Str(s)),
        Token::Sep(_) => None,
    }).collect()
}

fn is_trivial(item: &Item) -> bool {
    match item {
        Item::Int(0) => true,
        Item::Str(s) => qualifier_order(s.as_str()) == Some(0),
        _ => false,
    }
}

fn strip_trivial_tail(mut items: Vec<Item>) -> Vec<Item> {
    while let Some(last) = items.last() {
        if is_trivial(last) {
            items.pop();
        } else {
            break;
        }
    }
    items
}

fn compare_tokens(ta: &Item, tb: &Item) -> Ordering {
    match (ta, tb) {
        (Item::Int(a), Item::Int(b)) => a.cmp(b),
        (Item::Int(_), Item::Str(_)) => Ordering::Greater, // numeric > qualifier
        (Item::Str(_), Item::Int(_)) => Ordering::Less,
        (Item::Str(a), Item::Str(b)) => {
            let oa = qualifier_order(a.as_str());
            let ob = qualifier_order(b.as_str());
            match (oa, ob) {
                (Some(x), Some(y)) => x.cmp(&y),
                (Some(_), None) => Ordering::Less,   // known < unknown
                (None, Some(_)) => Ordering::Greater, // unknown > known
                (None, None) => a.cmp(b),
            }
        }
    }
}

fn compare_extra(extras: &[Item]) -> Ordering {
    for item in extras {
        match item {
            Item::Int(v) => {
                if *v != 0 {
                    return if *v > 0 { Ordering::Greater } else { Ordering::Less };
                }
            }
            Item::Str(s) => {
                match qualifier_order(s.as_str()) {
                    None => return Ordering::Greater,
                    Some(o) if o < 0 => return Ordering::Less,
                    Some(o) if o > 0 => return Ordering::Greater,
                    _ => {} // order == 0 is trivial
                }
            }
        }
    }
    Ordering::Equal
}

pub fn compare(a: &str, b: &str) -> Result<i32, String> {
    if a == b {
        return Ok(0);
    }
    let ia = strip_trivial_tail(items(a));
    let ib = strip_trivial_tail(items(b));

    for (ta, tb) in ia.iter().zip(ib.iter()) {
        match compare_tokens(ta, tb) {
            Ordering::Less => return Ok(-1),
            Ordering::Greater => return Ok(1),
            Ordering::Equal => {}
        }
    }
    if ia.len() == ib.len() {
        return Ok(0);
    }
    if ia.len() < ib.len() {
        // Extra tokens in b — negate compare_extra for b's extras
        let result = compare_extra(&ib[ia.len()..]);
        return Ok(match result {
            Ordering::Less => 1,
            Ordering::Greater => -1,
            Ordering::Equal => 0,
        });
    }
    // Extra tokens in a
    let result = compare_extra(&ia[ib.len()..]);
    Ok(match result {
        Ordering::Less => -1,
        Ordering::Greater => 1,
        Ordering::Equal => 0,
    })
}
