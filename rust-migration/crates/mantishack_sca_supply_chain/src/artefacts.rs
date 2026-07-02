//! Disguised/obfuscated-artefact heuristics — Rust port of the pure content
//! functions in `packages/sca/supply_chain/artefacts.py`.
//!
//! Shannon entropy, magic-byte payload classification, extension/magic mismatch
//! ("disguised filename"), and the minified/obfuscated size+entropy check. The
//! filesystem walk + finding assembly stay call-site in Python and drive these
//! on already-read bytes.

const OBFUSC_MIN_BYTES: u64 = 100 * 1024;
const OBFUSC_MAX_LINE_LEN: usize = 1000;
const OBFUSC_HIGH_ENTROPY: f64 = 5.5;

const BINARY_MAGIC: &[&[u8]] = &[
    b"\x7fELF",
    b"MZ",
    b"\xCA\xFE\xBA\xBE",
    b"\xFE\xED\xFA\xCE",
    b"\xFE\xED\xFA\xCF",
    b"\xCF\xFA\xED\xFE",
    b"PK\x03\x04",
    b"\x1f\x8b",
];

const SHEBANG_OK_EXTS: &[&str] =
    &[".sh", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl", ".lua", ".ts", ".rs", ".go"];

/// Bit-entropy per byte (`_shannon_entropy`); `0.0 <= result <= 8.0`.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c != 0)
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Classify a binary payload from its head bytes (`_classify_binary_payload`).
pub fn classify_binary_payload(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(b"\x7fELF") {
        return Some("an ELF executable");
    }
    if head.starts_with(b"MZ") {
        return Some("a Windows PE/COFF executable");
    }
    if head.starts_with(b"PK\x03\x04") {
        return Some("a ZIP/JAR archive");
    }
    if head.starts_with(b"\x1f\x8b") {
        return Some("a gzip-compressed payload");
    }
    for m in [
        b"\xCA\xFE\xBA\xBE".as_slice(),
        b"\xFE\xED\xFA\xCE",
        b"\xFE\xED\xFA\xCF",
        b"\xCF\xFA\xED\xFE",
    ] {
        if head.starts_with(m) {
            return Some("a Java class or Mach-O binary");
        }
    }
    for m in [b"#!/bin/sh".as_slice(), b"#!/bin/bash", b"#!/usr/bin/env"] {
        if head.starts_with(m) {
            return Some("an executable shell script");
        }
    }
    let head8 = &head[..head.len().min(8)];
    if head.first() == Some(&b'#') && head8.contains(&b'!') {
        return Some("an executable shebanged script");
    }
    None
}

/// Magic-byte signatures for an extension, or `None` for text/unknown
/// extensions (both take the text-branch in `check_disguised_filename_head`,
/// mirroring Python's `.get(suffix)` collapsing absent and `None` values).
fn extension_magic(suffix: &str) -> Option<&'static [&'static [u8]]> {
    match suffix {
        ".png" => Some(&[b"\x89PNG\r\n\x1a\n"]),
        ".jpg" | ".jpeg" => Some(&[b"\xff\xd8\xff"]),
        ".gif" => Some(&[b"GIF87a", b"GIF89a"]),
        ".webp" => Some(&[b"RIFF"]),
        ".bmp" => Some(&[b"BM"]),
        ".ico" => Some(&[b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"]),
        ".pdf" => Some(&[b"%PDF-"]),
        ".mp3" => Some(&[b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"]),
        ".mp4" => Some(&[b"\x00\x00\x00\x18ftyp", b"\x00\x00\x00 ftyp"]),
        ".zip" => Some(&[b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"]),
        ".jar" => Some(&[b"PK\x03\x04"]),
        ".gz" => Some(&[b"\x1f\x8b"]),
        ".7z" => Some(&[b"7z\xbc\xaf\x27\x1c"]),
        _ => None,
    }
}

/// Describe how a file's head bytes disguise its true type, or `None`
/// (`_check_disguised_filename`, given already-read `head`, up to 512 bytes).
pub fn check_disguised_filename_head(head: &[u8], suffix: &str) -> Option<String> {
    if head.is_empty() {
        return None;
    }
    match extension_magic(suffix) {
        None => {
            // Text-typed (or unknown) extension: the head must look like text.
            let head256 = &head[..head.len().min(256)];
            if head256.contains(&0) {
                return Some(classify_binary_payload(head).unwrap_or("embedded null bytes").to_string());
            }
            for sig in BINARY_MAGIC {
                if head.starts_with(sig) {
                    return Some(classify_binary_payload(head).unwrap_or("an unrelated binary format").to_string());
                }
            }
            if !SHEBANG_OK_EXTS.contains(&suffix) && head.starts_with(b"#!") {
                return Some(classify_binary_payload(head).unwrap_or("an executable shebanged script").to_string());
            }
            None
        }
        Some(magics) => {
            for magic in magics {
                if head.starts_with(magic) {
                    return None;
                }
            }
            Some(classify_binary_payload(head).unwrap_or("an unrelated binary format").to_string())
        }
    }
}

/// Format an integer with thousands separators (Python `{n:,}`).
fn py_comma(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, &c) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c as char);
    }
    out
}

/// Detect a minified/obfuscated large text artefact (`_check_obfuscated`).
/// `size` is the full file size; `data` is the (bounded) read content; `rel` is
/// the display path. The `< OBFUSC_MIN_BYTES` gate and read stay caller-side too,
/// but are re-checked here for fidelity.
pub fn check_obfuscated_content(data: &[u8], rel: &str, size: u64) -> Option<String> {
    if size < OBFUSC_MIN_BYTES || data.is_empty() {
        return None;
    }
    let mut longest = 0usize;
    let mut line_start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if b == 0x0a {
            longest = longest.max(i - line_start);
            line_start = i + 1;
        }
    }
    longest = longest.max(data.len() - line_start);

    let entropy = shannon_entropy(data);
    if longest > OBFUSC_MAX_LINE_LEN && entropy > OBFUSC_HIGH_ENTROPY {
        return Some(format!(
            "`{rel}` ({} bytes) has a {}-char line and entropy {:.1} bits/byte \u{2014} looks minified/obfuscated",
            py_comma(size),
            py_comma(longest as u64),
            entropy,
        ));
    }
    if longest > OBFUSC_MAX_LINE_LEN * 4 {
        return Some(format!(
            "`{rel}` ({} bytes) has a {}-char single line \u{2014} looks minified",
            py_comma(size),
            py_comma(longest as u64),
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy() {
        assert_eq!(shannon_entropy(b""), 0.0);
        let uniform: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&uniform) - 8.0).abs() < 1e-9);
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
        assert!((shannon_entropy(b"ab") - 1.0).abs() < 1e-9);
        assert!((shannon_entropy(b"aabbccdd") - 2.0).abs() < 1e-9);
    }

    #[test]
    fn classify() {
        assert_eq!(classify_binary_payload(b"\x7fELF\x02\x01"), Some("an ELF executable"));
        assert_eq!(classify_binary_payload(b"MZ\x90\x00"), Some("a Windows PE/COFF executable"));
        assert_eq!(classify_binary_payload(b"PK\x03\x04"), Some("a ZIP/JAR archive"));
        assert_eq!(classify_binary_payload(b"\x1f\x8bxx"), Some("a gzip-compressed payload"));
        assert_eq!(classify_binary_payload(b"\xCA\xFE\xBA\xBE"), Some("a Java class or Mach-O binary"));
        assert_eq!(classify_binary_payload(b"#!/bin/sh\n"), Some("an executable shell script"));
        assert_eq!(classify_binary_payload(b"#!x!yy"), Some("an executable shebanged script"));
        assert_eq!(classify_binary_payload(b"hello world"), None);
    }

    #[test]
    fn disguise() {
        let mut null_txt = b"abc\x00def".to_vec();
        null_txt.extend_from_slice(&[b'x'; 10]);
        assert_eq!(check_disguised_filename_head(&null_txt, ".json").as_deref(), Some("embedded null bytes"));
        let mut elf = b"\x7fELF".to_vec();
        elf.extend_from_slice(&[0u8; 10]);
        assert_eq!(check_disguised_filename_head(&elf, ".txt").as_deref(), Some("an ELF executable"));
        assert_eq!(check_disguised_filename_head(b"#!/bin/sh\necho hi", ".json").as_deref(), Some("an executable shell script"));
        assert_eq!(check_disguised_filename_head(b"#!/bin/sh\necho hi", ".py"), None);
        assert_eq!(check_disguised_filename_head(b"\x89PNG\r\n\x1a\ndata", ".png"), None);
        assert_eq!(check_disguised_filename_head(b"\x7fELFxx", ".png").as_deref(), Some("an ELF executable"));
        assert_eq!(check_disguised_filename_head(b"just text here", ".txt"), None);
        assert_eq!(check_disguised_filename_head(b"", ".txt"), None);
    }

    #[test]
    fn obfuscated() {
        assert_eq!(check_obfuscated_content(b"x".repeat(100).as_slice(), "a.js", 100), None);
        let long_line = b"a".repeat(200 * 1024);
        assert_eq!(
            check_obfuscated_content(&long_line, "b.js", 204800).as_deref(),
            Some("`b.js` (204,800 bytes) has a 204,800-char single line \u{2014} looks minified")
        );
        // High-entropy data that includes newline bytes -> short lines -> no flag.
        let highent: Vec<u8> = (0..200 * 1024).map(|i: usize| ((i * 37 + 11) % 256) as u8).collect();
        assert_eq!(check_obfuscated_content(&highent, "c.js", highent.len() as u64), None);
    }

    #[test]
    fn obfuscated_high_entropy_single_line() {
        // A long, newline-free, high-entropy line trips the first branch.
        let mut data: Vec<u8> = (0..2000u32).map(|i| ((i * 37 + 11) % 256) as u8).filter(|&b| b != 0x0a).collect();
        while data.len() < 150 * 1024 {
            let chunk: Vec<u8> = data.clone();
            data.extend(chunk.into_iter().filter(|&b| b != 0x0a));
        }
        let n = data.len() as u64;
        let out = check_obfuscated_content(&data, "d.js", n).unwrap();
        assert!(out.contains("looks minified/obfuscated"), "{out}");
        assert!(out.contains("bits/byte"));
    }
}
