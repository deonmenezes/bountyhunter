//! Dataclasses for the checker-synthesis pipeline — faithful port of
//! `packages/checker_synthesis/models.py`. Kept simple and serialisable so
//! `/audit` can persist synthesis attempts as JSON alongside its annotations.

use serde_json::{Map, Value};

/// Synthesis verdicts for an individual cross-codebase match.
pub const TRIAGE_STATUSES: [&str; 4] = ["variant", "false_positive", "uncertain", "skipped"];

/// The confirmed bug that seeds a synthesis attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedBug {
    pub file: String, // repo-relative path
    pub function: String,
    pub line_start: i64,
    pub line_end: i64,
    pub cwe: String,
    pub reasoning: String,
    pub snippet: String, // function source text; "" when unavailable
}

impl SeedBug {
    /// Mirror the Python dataclass default `snippet: str = ""`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        file: String,
        function: String,
        line_start: i64,
        line_end: i64,
        cwe: String,
        reasoning: String,
        snippet: Option<String>,
    ) -> Self {
        SeedBug {
            file,
            function,
            line_start,
            line_end,
            cwe,
            reasoning,
            snippet: snippet.unwrap_or_default(),
        }
    }
}

/// One LLM-proposed checker rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynthesisedRule {
    pub engine: String, // "semgrep" or "coccinelle"
    pub rule_id: String,
    pub body: String,
    pub rationale: String, // "" default
}

impl SynthesisedRule {
    pub fn new(engine: String, rule_id: String, body: String, rationale: Option<String>) -> Self {
        SynthesisedRule {
            engine,
            rule_id,
            body,
            rationale: rationale.unwrap_or_default(),
        }
    }
}

/// One cross-codebase hit from running a synthesised rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub file: String, // repo-relative
    pub line: i64,
    pub snippet: String, // "" default
    /// Ordered to preserve Python dict insertion order in `to_dict`.
    pub metavars: Vec<(String, String)>,
}

impl Match {
    pub fn new(file: String, line: i64, snippet: Option<String>, metavars: Option<Vec<(String, String)>>) -> Self {
        Match {
            file,
            line,
            snippet: snippet.unwrap_or_default(),
            metavars: metavars.unwrap_or_default(),
        }
    }
}

/// Per-match LLM verdict from the optional triage pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchTriage {
    pub match_: Match,
    pub status: String, // one of TRIAGE_STATUSES
    pub reasoning: String, // "" default
}

impl MatchTriage {
    pub fn new(match_: Match, status: String, reasoning: Option<String>) -> Self {
        MatchTriage {
            match_,
            status,
            reasoning: reasoning.unwrap_or_default(),
        }
    }
}

/// Top-level output of `synthesise_and_run`.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckerSynthesisResult {
    pub seed: SeedBug,
    pub rule: Option<SynthesisedRule>,
    pub rule_path: Option<String>, // str(Path) or None
    pub positive_control: bool,
    pub matches: Vec<Match>,
    pub triage: Vec<MatchTriage>,
    pub capped: bool,
    pub errors: Vec<String>,
}

impl CheckerSynthesisResult {
    /// Mirror the dataclass field defaults (everything but `seed`).
    pub fn new(seed: SeedBug) -> Self {
        CheckerSynthesisResult {
            seed,
            rule: None,
            rule_path: None,
            positive_control: false,
            matches: Vec::new(),
            triage: Vec::new(),
            capped: false,
            errors: Vec::new(),
        }
    }

    /// JSON-serialisable view for persistence — byte-for-byte the same key
    /// order and shape as the Python `to_dict`.
    pub fn to_dict(&self) -> Value {
        let mut root = Map::new();

        let mut seed = Map::new();
        seed.insert("file".into(), Value::String(self.seed.file.clone()));
        seed.insert("function".into(), Value::String(self.seed.function.clone()));
        seed.insert("line_start".into(), Value::from(self.seed.line_start));
        seed.insert("line_end".into(), Value::from(self.seed.line_end));
        seed.insert("cwe".into(), Value::String(self.seed.cwe.clone()));
        seed.insert("reasoning".into(), Value::String(self.seed.reasoning.clone()));
        root.insert("seed".into(), Value::Object(seed));

        root.insert(
            "rule".into(),
            match &self.rule {
                None => Value::Null,
                Some(r) => {
                    let mut m = Map::new();
                    m.insert("engine".into(), Value::String(r.engine.clone()));
                    m.insert("rule_id".into(), Value::String(r.rule_id.clone()));
                    m.insert("body".into(), Value::String(r.body.clone()));
                    m.insert("rationale".into(), Value::String(r.rationale.clone()));
                    Value::Object(m)
                }
            },
        );

        root.insert(
            "rule_path".into(),
            match &self.rule_path {
                Some(p) => Value::String(p.clone()),
                None => Value::Null,
            },
        );
        root.insert("positive_control".into(), Value::Bool(self.positive_control));

        let matches: Vec<Value> = self
            .matches
            .iter()
            .map(|m| {
                let mut mm = Map::new();
                mm.insert("file".into(), Value::String(m.file.clone()));
                mm.insert("line".into(), Value::from(m.line));
                mm.insert("snippet".into(), Value::String(m.snippet.clone()));
                let mut mv = Map::new();
                for (k, v) in &m.metavars {
                    mv.insert(k.clone(), Value::String(v.clone()));
                }
                mm.insert("metavars".into(), Value::Object(mv));
                Value::Object(mm)
            })
            .collect();
        root.insert("matches".into(), Value::Array(matches));

        let triage: Vec<Value> = self
            .triage
            .iter()
            .map(|t| {
                let mut tt = Map::new();
                let mut mm = Map::new();
                mm.insert("file".into(), Value::String(t.match_.file.clone()));
                mm.insert("line".into(), Value::from(t.match_.line));
                mm.insert("snippet".into(), Value::String(t.match_.snippet.clone()));
                tt.insert("match".into(), Value::Object(mm));
                tt.insert("status".into(), Value::String(t.status.clone()));
                tt.insert("reasoning".into(), Value::String(t.reasoning.clone()));
                Value::Object(tt)
            })
            .collect();
        root.insert("triage".into(), Value::Array(triage));

        root.insert("capped".into(), Value::Bool(self.capped));
        root.insert(
            "errors".into(),
            Value::Array(self.errors.iter().cloned().map(Value::String).collect()),
        );

        Value::Object(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> SeedBug {
        SeedBug::new(
            "src/foo.py".into(),
            "login".into(),
            10,
            20,
            "CWE-89".into(),
            "r".into(),
            None,
        )
    }

    #[test]
    fn seedbug_default_snippet_empty() {
        let s = SeedBug::new(
            "src/foo.py".into(),
            "login".into(),
            10,
            20,
            "CWE-89".into(),
            "Tainted query string reaches cursor.execute".into(),
            None,
        );
        assert_eq!(s.file, "src/foo.py");
        assert_eq!(s.snippet, "");
    }

    #[test]
    fn default_failure_state() {
        let r = CheckerSynthesisResult::new(seed());
        assert!(r.rule.is_none());
        assert!(r.matches.is_empty());
        assert!(r.triage.is_empty());
        assert!(!r.capped);
        assert!(r.errors.is_empty());
        assert!(!r.positive_control);
    }

    #[test]
    fn to_dict_no_rule() {
        let mut r = CheckerSynthesisResult::new(seed());
        r.errors = vec!["LLM unavailable".into()];
        let d = r.to_dict();
        assert_eq!(d["rule"], Value::Null);
        assert_eq!(d["matches"], Value::Array(vec![]));
        assert_eq!(d["errors"], serde_json::json!(["LLM unavailable"]));
        // JSON-serialisable.
        assert!(serde_json::to_string(&d).is_ok());
    }

    #[test]
    fn to_dict_with_rule_and_matches() {
        let rule = SynthesisedRule::new("semgrep".into(), "x.0".into(), "rules: ...".into(), None);
        let m = Match::new("src/bar.py".into(), 5, Some("db.execute(q)".into()), None);
        let t = MatchTriage::new(m.clone(), "variant".into(), Some("Same pattern, different file".into()));
        let mut r = CheckerSynthesisResult::new(seed());
        r.rule = Some(rule);
        r.rule_path = Some("/tmp/x.yml".into());
        r.positive_control = true;
        r.matches = vec![m];
        r.triage = vec![t];
        let d = r.to_dict();
        assert_eq!(d["rule"]["engine"], "semgrep");
        assert_eq!(d["matches"][0]["file"], "src/bar.py");
        assert_eq!(d["triage"][0]["status"], "variant");
        assert_eq!(d["positive_control"], Value::Bool(true));
        assert!(serde_json::to_string(&d).is_ok());
    }

    #[test]
    fn to_dict_key_order_matches_python() {
        // preserve_order → top-level keys in Python insertion order.
        let r = CheckerSynthesisResult::new(seed());
        let d = r.to_dict();
        let keys: Vec<&String> = d.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            vec!["seed", "rule", "rule_path", "positive_control", "matches", "triage", "capped", "errors"]
        );
    }

    #[test]
    fn triage_statuses_constant() {
        assert_eq!(TRIAGE_STATUSES, ["variant", "false_positive", "uncertain", "skipped"]);
    }
}
