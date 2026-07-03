//! Prompt templates for checker synthesis + match triage — faithful port of
//! `packages/checker_synthesis/prompts.py`. Pure string construction; the
//! schemas double as in-prompt documentation.

use serde_json::{json, Value};

use crate::models::{Match, SeedBug, SynthesisedRule};

/// Cap on `seed.snippet` going into the synthesis prompt (UTF-8 bytes).
const SEED_SNIPPET_MAX_BYTES: usize = 8_192;

/// Cap `snippet` at `SEED_SNIPPET_MAX_BYTES` UTF-8 bytes; on truncation append
/// a marker. Mirrors Python `.encode("utf-8")[:cap].decode("utf-8", "ignore")`
/// — for valid-UTF-8 input this is the longest valid prefix of the byte cut.
pub fn truncate_snippet(snippet: &str) -> String {
    let bytes = snippet.as_bytes();
    if bytes.len() <= SEED_SNIPPET_MAX_BYTES {
        return snippet.to_string();
    }
    let cut = &bytes[..SEED_SNIPPET_MAX_BYTES];
    let truncated = match std::str::from_utf8(cut) {
        Ok(s) => s.to_string(),
        // errors="ignore" drops the split trailing bytes; keep the valid prefix.
        Err(e) => String::from_utf8(cut[..e.valid_up_to()].to_vec()).unwrap(),
    };
    format!("{truncated}\n... (snippet truncated)")
}

// --- Synthesis ------------------------------------------------------------

pub const SYNTHESIS_SYSTEM: &str = concat!(
    "You are a security analyst translating a confirmed code-level bug ",
    "into a static analysis rule. The rule must:\n",
    "  1. Match the original bug's pattern (positive control).\n",
    "  2. Be tight enough that running it across the codebase surfaces ",
    "VARIANTS of the same bug class — not every superficially similar ",
    "construct.\n",
    "  3. Be syntactically valid for the chosen engine (Semgrep YAML ",
    "or Coccinelle .cocci).\n\n",
    "Avoid rules that match every call to a common API (e.g. every ",
    "``subprocess.run``). Match the structural shape that makes the ",
    "ORIGINAL bug unsafe — typically the absence of a check, the use ",
    "of a tainted value at a sink, or a missing cleanup."
);

/// The synthesis response schema (LLM output contract).
pub fn synthesis_schema() -> Value {
    json!({
        "type": "object",
        "required": ["rule_body", "rationale"],
        "properties": {
            "rule_body": {
                "type": "string",
                "description": "The complete rule text — Semgrep YAML or Coccinelle .cocci syntax depending on engine. Must be valid as written (no placeholders, no '...' literals as code)."
            },
            "rationale": {
                "type": "string",
                "description": "One paragraph explaining what structural pattern this rule captures and why a variant matching this rule is likely to be the same bug class."
            }
        }
    })
}

/// Compose the synthesis prompt body.
pub fn build_synthesis_prompt(
    seed: &SeedBug,
    engine: &str,
    retry_feedback: &str,
    prior_fps: &[Match],
) -> String {
    let reasoning = {
        let t = seed.reasoning.trim();
        if t.is_empty() { "(no reasoning provided)" } else { t }
    };
    let mut parts: Vec<String> = vec![
        format!("BUG TO REPLICATE AS A CHECKER ({engine})"),
        String::new(),
        format!("File:     {}", seed.file),
        format!("Function: {}", seed.function),
        format!("Lines:    {}–{}", seed.line_start, seed.line_end),
        format!("CWE:      {}", seed.cwe),
        String::new(),
        "Reasoning from the original analysis:".to_string(),
        reasoning.to_string(),
    ];
    if !seed.snippet.is_empty() {
        parts.push(String::new());
        parts.push("Source of the buggy function:".to_string());
        parts.push("```".to_string());
        parts.push(truncate_snippet(&seed.snippet).trim_end().to_string());
        parts.push("```".to_string());
    }
    parts.push(String::new());
    parts.push("TASK:".to_string());
    parts.push(format!("Output a {engine} rule that:"));
    parts.push("  1. Matches the original bug at the lines above.".to_string());
    parts.push("  2. Captures the structural shape, not the exact text — so running it across the codebase finds variants that share the same flaw.".to_string());
    parts.push("  3. Is tight enough to avoid mass false positives. If your first instinct is a single ``pattern: foo(...)`` that would match every call to ``foo``, refine it.".to_string());
    parts.push(String::new());
    parts.push("Respond with JSON: {\"rule_body\": \"...\", \"rationale\": \"...\"}.".to_string());

    if !retry_feedback.is_empty() {
        parts.push(String::new());
        parts.push("RETRY — the previous attempt failed:".to_string());
        parts.push(retry_feedback.to_string());
        parts.push("Refine the rule, don't regenerate from scratch.".to_string());
    }

    if !prior_fps.is_empty() {
        parts.push(String::new());
        parts.push("PRIOR FALSE POSITIVES — earlier rules matched the following locations that triage classified as NOT the same bug. Refine your rule to AVOID matching these while still hitting the seed at the lines above:".to_string());
        for fp in prior_fps.iter().take(8) {
            let mut line = format!("  - {}:{}", fp.file, fp.line);
            if !fp.snippet.is_empty() {
                let snip: String = fp
                    .snippet
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .chars()
                    .take(160)
                    .collect();
                line.push_str(&format!("\n      {snip}"));
            }
            parts.push(line);
        }
        if prior_fps.len() > 8 {
            parts.push(format!("  ... ({} more false positives elided)", prior_fps.len() - 8));
        }
    }
    parts.join("\n")
}

// --- Triage ---------------------------------------------------------------

pub const TRIAGE_SYSTEM: &str = concat!(
    "You are evaluating whether a candidate match is the same bug ",
    "class as the seed bug, or a false positive of the synthesised ",
    "rule. Be strict: 'variant' requires the same underlying flaw, ",
    "not just superficial syntactic similarity. When the snippet ",
    "lacks context to decide confidently, return 'uncertain' rather ",
    "than guessing."
);

/// The triage response schema.
pub fn triage_schema() -> Value {
    json!({
        "type": "object",
        "required": ["status", "reasoning"],
        "properties": {
            "status": {
                "type": "string",
                "enum": ["variant", "false_positive", "uncertain"]
            },
            "reasoning": {
                "type": "string",
                "description": "One short paragraph justifying the verdict."
            }
        }
    })
}

/// Compose the triage prompt for one candidate match.
pub fn build_triage_prompt(seed: &SeedBug, rule: &SynthesisedRule, m: &Match) -> String {
    let reasoning = {
        let t = seed.reasoning.trim();
        if t.is_empty() { "(none)" } else { t }
    };
    let rationale = if rule.rationale.is_empty() { "(none)" } else { &rule.rationale };
    let mut parts: Vec<String> = vec![
        "SEED BUG (the confirmed instance, used as ground truth):".to_string(),
        format!("  File:     {}", seed.file),
        format!("  Function: {}", seed.function),
        format!("  Lines:    {}–{}", seed.line_start, seed.line_end),
        format!("  CWE:      {}", seed.cwe),
        format!("  Reasoning: {reasoning}"),
        String::new(),
        format!("SYNTHESISED RULE ({}, id={}):", rule.engine, rule.rule_id),
        format!("  Rationale: {rationale}"),
        String::new(),
        "CANDIDATE MATCH (rule fired here, same bug or false positive?):".to_string(),
        format!("  File: {}", m.file),
        format!("  Line: {}", m.line),
    ];
    if !m.snippet.is_empty() {
        parts.push("  Snippet:".to_string());
        parts.push("  ```".to_string());
        parts.push(format!("  {}", m.snippet.trim_end().replace('\n', "\n  ")));
        parts.push("  ```".to_string());
    }
    parts.push(String::new());
    parts.push("TASK: classify this match.".to_string());
    parts.push("  * variant         — same underlying flaw as the seed bug.".to_string());
    parts.push("  * false_positive  — the rule matched but the code is safe.".to_string());
    parts.push("  * uncertain       — not enough context to decide.".to_string());
    parts.push(String::new());
    parts.push("Respond with JSON: {\"status\": \"variant|false_positive|uncertain\", \"reasoning\": \"...\"}.".to_string());
    parts.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> SeedBug {
        SeedBug::new("src/foo.py".into(), "login".into(), 10, 20, "CWE-89".into(), "Tainted value at sink".into(), None)
    }

    #[test]
    fn synthesis_prompt_core_lines() {
        let p = build_synthesis_prompt(&seed(), "semgrep", "", &[]);
        assert!(p.starts_with("BUG TO REPLICATE AS A CHECKER (semgrep)\n"));
        assert!(p.contains("File:     src/foo.py"));
        assert!(p.contains("Function: login"));
        // en-dash between line numbers
        assert!(p.contains("Lines:    10\u{2013}20"));
        assert!(p.contains("CWE:      CWE-89"));
        assert!(p.contains("Reasoning from the original analysis:\nTainted value at sink"));
        assert!(p.contains("Output a semgrep rule that:"));
        assert!(p.ends_with("Respond with JSON: {\"rule_body\": \"...\", \"rationale\": \"...\"}."));
        // no snippet section when snippet empty
        assert!(!p.contains("Source of the buggy function:"));
    }

    #[test]
    fn synthesis_prompt_empty_reasoning_placeholder() {
        let mut s = seed();
        s.reasoning = "   ".into();
        let p = build_synthesis_prompt(&s, "semgrep", "", &[]);
        assert!(p.contains("Reasoning from the original analysis:\n(no reasoning provided)"));
    }

    #[test]
    fn synthesis_prompt_snippet_and_retry_and_fps() {
        let mut s = seed();
        s.snippet = "def f():\n    run(x)\n\n".into();
        let fp1 = Match::new("a/b.py".into(), 3, Some("  foo(  bar )  ".into()), None);
        let mut fps = vec![fp1];
        for i in 0..9 {
            fps.push(Match::new(format!("f{i}.py"), i, None, None));
        }
        let p = build_synthesis_prompt(&s, "coccinelle", "rule did not match", &fps);
        // snippet block rstrip-ped
        assert!(p.contains("Source of the buggy function:\n```\ndef f():\n    run(x)\n```"));
        // retry block with em-dash
        assert!(p.contains("RETRY \u{2014} the previous attempt failed:\nrule did not match\nRefine the rule, don't regenerate from scratch."));
        // prior FP header + collapsed snippet + elision (10 fps -> 8 shown, 2 elided)
        assert!(p.contains("  - a/b.py:3\n      foo( bar )"));
        assert!(p.contains("  ... (2 more false positives elided)"));
    }

    #[test]
    fn triage_prompt_shape() {
        let rule = SynthesisedRule::new("semgrep".into(), "auth.login.cwe-89.0".into(), "rules: ...".into(), Some("catches tainted SQL".into()));
        let m = Match::new("src/bar.py".into(), 42, Some("db.execute(q)\nnext".into()), None);
        let p = build_triage_prompt(&seed(), &rule, &m);
        assert!(p.starts_with("SEED BUG (the confirmed instance, used as ground truth):\n"));
        assert!(p.contains("  Lines:    10\u{2013}20"));
        assert!(p.contains("SYNTHESISED RULE (semgrep, id=auth.login.cwe-89.0):"));
        assert!(p.contains("  Rationale: catches tainted SQL"));
        // snippet indented, newline re-indented
        assert!(p.contains("  ```\n  db.execute(q)\n  next\n  ```"));
        assert!(p.contains("  * variant         \u{2014} same underlying flaw as the seed bug."));
        assert!(p.ends_with("Respond with JSON: {\"status\": \"variant|false_positive|uncertain\", \"reasoning\": \"...\"}."));
    }

    #[test]
    fn triage_prompt_placeholders() {
        let rule = SynthesisedRule::new("coccinelle".into(), "x".into(), "b".into(), None);
        let mut s = seed();
        s.reasoning = "".into();
        let m = Match::new("z.c".into(), 1, None, None);
        let p = build_triage_prompt(&s, &rule, &m);
        assert!(p.contains("  Reasoning: (none)"));
        assert!(p.contains("  Rationale: (none)"));
        // no snippet block
        assert!(!p.contains("  Snippet:"));
    }

    #[test]
    fn truncate_snippet_passthrough_and_cut() {
        assert_eq!(truncate_snippet("short"), "short");
        let big = "a".repeat(9000);
        let out = truncate_snippet(&big);
        assert!(out.ends_with("\n... (snippet truncated)"));
        assert_eq!(out.len(), 8192 + "\n... (snippet truncated)".len());
    }

    #[test]
    fn schemas_shape() {
        assert_eq!(synthesis_schema()["required"], json!(["rule_body", "rationale"]));
        assert_eq!(triage_schema()["properties"]["status"]["enum"], json!(["variant", "false_positive", "uncertain"]));
    }
}
