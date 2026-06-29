use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

const FIXTURE_PATH_PATTERNS: &[(&str, &str)] = &[
    (r"(^|/)tests?/", "tests directory"),
    (r"(^|/)__tests__/", "JS __tests__ directory"),
    (r"(^|/)spec/", "spec directory (Ruby/JS/etc.)"),
    (r"(^|/)testdata/", "Go testdata directory"),
    (r"(^|/)fixtures?/", "fixtures directory"),
    (r"(^|/)test_[^/]+\.py$", "Python test_*.py"),
    (r"(^|/)[^/]+_test\.py$", "Python *_test.py"),
    (r"(^|/)conftest\.py$", "pytest conftest.py"),
    (r"(^|/)[^/]+_test\.go$", "Go *_test.go"),
    (
        r"(^|/)[^/]+\.test\.[jt]sx?$",
        "JS/TS *.test.{js,ts,jsx,tsx}",
    ),
    (
        r"(^|/)[^/]+\.spec\.[jt]sx?$",
        "JS/TS *.spec.{js,ts,jsx,tsx}",
    ),
    (r"(^|/)Test[A-Z][^/]*\.java$", "Java Test*.java"),
    (r"(^|/)[^/]+Test\.java$", "Java *Test.java"),
];

fn fixture_patterns() -> &'static Vec<(Regex, &'static str)> {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        FIXTURE_PATH_PATTERNS
            .iter()
            .map(|(pattern, label)| (Regex::new(pattern).unwrap(), *label))
            .collect()
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarnessEvidence {
    pub kind: String,
    pub path: String,
    pub pattern: String,
    pub result: String,
    pub checked_against: Vec<String>,
}

impl HarnessEvidence {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            path: String::new(),
            pattern: String::new(),
            result: String::new(),
            checked_against: Vec::new(),
        }
    }

    pub fn to_dict(&self) -> Value {
        let mut result = Map::new();
        result.insert("type".into(), Value::String(self.kind.clone()));
        if !self.path.is_empty() {
            result.insert("path".into(), Value::String(self.path.clone()));
        }
        if !self.pattern.is_empty() {
            result.insert("pattern".into(), Value::String(self.pattern.clone()));
        }
        if !self.result.is_empty() {
            result.insert("result".into(), Value::String(self.result.clone()));
        }
        if !self.checked_against.is_empty() {
            result.insert("checked_against".into(), json!(self.checked_against));
        }
        Value::Object(result)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureVerdict {
    pub likely_test_harness: String,
    pub evidence: Vec<HarnessEvidence>,
}

impl FixtureVerdict {
    pub fn to_dict(&self) -> Value {
        json!({
            "likely_test_harness": self.likely_test_harness,
            "harness_evidence": self.evidence.iter().map(HarnessEvidence::to_dict).collect::<Vec<_>>()
        })
    }
}

pub fn is_fixture_path(file_path: &str) -> (bool, String) {
    if file_path.is_empty() {
        return (false, String::new());
    }
    let normalized = file_path.replace('\\', "/");
    fixture_patterns()
        .iter()
        .find_map(|(pattern, label)| {
            pattern
                .is_match(&normalized)
                .then(|| (true, (*label).to_string()))
        })
        .unwrap_or((false, String::new()))
}

pub fn default_qualified_name(file_path: &str, function: &str) -> String {
    if file_path.is_empty() || function.is_empty() {
        return String::new();
    }
    let mut normalized = file_path.replace('\\', "/");
    for extension in [".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb"] {
        if normalized.ends_with(extension) {
            normalized.truncate(normalized.len() - extension.len());
            break;
        }
    }
    let mut parts: Vec<_> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    parts.push(function);
    parts.join(".")
}

/// Execute the portion of `detect_fixture` that does not require the
/// reachability index. The full gate is completed once `reachability` lands.
pub fn detect_fixture_without_reachability(
    file_path: &str,
    function: &str,
    inventory_has_files: bool,
    qualified_name: Option<&str>,
) -> FixtureVerdict {
    let (matched, label) = is_fixture_path(file_path);
    if !matched {
        return FixtureVerdict {
            likely_test_harness: "false".into(),
            evidence: Vec::new(),
        };
    }

    let mut path_evidence = HarnessEvidence::new("fixture_path_match");
    path_evidence.path = file_path.to_string();
    path_evidence.pattern = label;
    let mut evidence = vec![path_evidence];
    let qualified_name = qualified_name
        .map(ToString::to_string)
        .unwrap_or_else(|| default_qualified_name(file_path, function));
    if !inventory_has_files || qualified_name.is_empty() || !qualified_name.contains('.') {
        let mut missing = HarnessEvidence::new("reachability_check");
        missing.result = "data_missing".into();
        evidence.push(missing);
        return FixtureVerdict {
            likely_test_harness: "candidate".into(),
            evidence,
        };
    }
    FixtureVerdict {
        likely_test_harness: "candidate".into(),
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_path_vectors_match_python() {
        let matches = [
            ("tests/conftest.py", "tests directory"),
            ("src/__tests__/Foo.test.tsx", "JS __tests__ directory"),
            ("spec/lib/foo_spec.rb", "spec directory (Ruby/JS/etc.)"),
            ("internal/testdata/sample.txt", "Go testdata directory"),
            ("fixtures/users.json", "fixtures directory"),
            ("test_runner.py", "Python test_*.py"),
            ("src/foo/bar_test.py", "Python *_test.py"),
            ("conftest.py", "pytest conftest.py"),
            ("src/foo_test.go", "Go *_test.go"),
            ("Foo.test.ts", "JS/TS *.test.{js,ts,jsx,tsx}"),
            ("Foo.spec.tsx", "JS/TS *.spec.{js,ts,jsx,tsx}"),
            ("src/main/java/TestRunner.java", "Java Test*.java"),
            ("src/main/java/RunnerTest.java", "Java *Test.java"),
        ];
        for (path, label) in matches {
            assert_eq!(is_fixture_path(path), (true, label.to_string()), "{path}");
        }
        for path in [
            "src/api/upload.py",
            "internal/handler.go",
            "src/contestant.py",
            "src/protest.go",
        ] {
            assert_eq!(is_fixture_path(path), (false, String::new()), "{path}");
        }
        assert_eq!(
            is_fixture_path(r"tests\sub\conftest.py").0,
            true
        );
    }

    #[test]
    fn early_fixture_verdicts_match_python() {
        assert_eq!(
            detect_fixture_without_reachability("src/api.py", "save", false, None)
                .likely_test_harness,
            "false"
        );
        let candidate =
            detect_fixture_without_reachability("tests/conftest.py", "setup", false, None);
        assert_eq!(candidate.likely_test_harness, "candidate");
        assert_eq!(candidate.evidence.len(), 2);
        assert_eq!(candidate.evidence[1].result, "data_missing");
    }

    #[test]
    fn qualified_name_vectors_match_python() {
        assert_eq!(
            default_qualified_name("src/foo/bar.py", "run"),
            "src.foo.bar.run"
        );
        assert_eq!(default_qualified_name("", "run"), "");
        assert_eq!(default_qualified_name("x.c", "run"), "x.c.run");
    }
}
