//! Goal-directed planning — Rust port of the pure classifier in
//! `packages/autonomous/goal_planner.py`.

use serde_json::{json, Value};

/// Types of goals the system can pursue (`GoalType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoalType {
    FindVulnerabilityType,
    TargetCodeArea,
    AchieveExploitType,
    MaximizeCoverage,
    FindAnyCrash,
}

impl GoalType {
    pub fn value(self) -> &'static str {
        match self {
            GoalType::FindVulnerabilityType => "find_vulnerability_type",
            GoalType::TargetCodeArea => "target_code_area",
            GoalType::AchieveExploitType => "achieve_exploit_type",
            GoalType::MaximizeCoverage => "maximize_coverage",
            GoalType::FindAnyCrash => "find_any_crash",
        }
    }
}

/// A high-level goal to achieve (`Goal`). `start_time` defaults to 0.0 here — the
/// Python `time.time()` default is a caller concern.
#[derive(Clone, Debug, PartialEq)]
pub struct Goal {
    pub goal_type: GoalType,
    pub description: String,
    pub target_value: Option<String>,
    pub progress: f64,
    pub achieved: bool,
    pub start_time: f64,
    pub strategy_hints: Value,
}

impl Goal {
    fn new(goal_type: GoalType, description: &str, target_value: Option<&str>, strategy_hints: Value) -> Self {
        Goal {
            goal_type,
            description: description.to_string(),
            target_value: target_value.map(str::to_string),
            progress: 0.0,
            achieved: false,
            start_time: 0.0,
            strategy_hints,
        }
    }
}

/// Parse user input into a structured goal (`create_goal_from_user_input`).
pub fn create_goal_from_user_input(user_goal: &str) -> Goal {
    let lower = user_goal.to_lowercase();
    let has = |s: &str| lower.contains(s);

    if ["heap overflow", "stack overflow", "use-after-free", "buffer overflow", "null pointer"].iter().any(|v| has(v)) {
        let target = if has("heap overflow") {
            "heap_overflow"
        } else if has("stack overflow") {
            "stack_overflow"
        } else if has("use-after-free") || has("uaf") {
            "use_after_free"
        } else if has("buffer overflow") {
            "buffer_overflow"
        } else {
            "memory_corruption"
        };
        return Goal::new(GoalType::FindVulnerabilityType, user_goal, Some(target),
            json!({"focus_on_memory": true, "enable_asan": true, "mutation_strategy": "aggressive"}));
    }

    if ["parser", "network", "authentication", "crypto"].iter().any(|v| has(v)) {
        let target = if has("parser") {
            "parser"
        } else if has("network") {
            "network"
        } else if has("auth") {
            "authentication"
        } else if has("crypto") {
            "cryptography"
        } else {
            "unknown"
        };
        return Goal::new(GoalType::TargetCodeArea, user_goal, Some(target),
            json!({"input_format": target, "mutation_strategy": "structured"}));
    }

    if ["rce", "code execution", "shell", "exploit"].iter().any(|v| has(v)) {
        return Goal::new(GoalType::AchieveExploitType, user_goal, Some("rce"),
            json!({"prioritize_exploitable": true, "deep_analysis": true}));
    }

    if has("coverage") || has("explore") {
        return Goal::new(GoalType::MaximizeCoverage, user_goal, None,
            json!({"mutation_strategy": "diverse", "parallel_instances": 4}));
    }

    Goal::new(GoalType::FindAnyCrash, user_goal, None, json!({"fast_mode": true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(inp: &str) -> (&'static str, Option<String>, Value) {
        let g = create_goal_from_user_input(inp);
        (g.goal_type.value(), g.target_value, g.strategy_hints)
    }

    #[test]
    fn vulnerability_types() {
        assert_eq!(classify("find heap overflow"), ("find_vulnerability_type", Some("heap_overflow".into()),
            json!({"focus_on_memory": true, "enable_asan": true, "mutation_strategy": "aggressive"})));
        assert_eq!(classify("stack overflow bug").1, Some("stack_overflow".into()));
        assert_eq!(classify("buffer overflow").1, Some("buffer_overflow".into()));
        assert_eq!(classify("null pointer deref").1, Some("memory_corruption".into()));
        // "uaf" alone doesn't pass the vuln gate (gate uses "use-after-free").
        assert_eq!(classify("UAF please").0, "find_any_crash");
    }

    #[test]
    fn code_area_exploit_coverage_default() {
        assert_eq!(classify("fuzz the parser"), ("target_code_area", Some("parser".into()),
            json!({"input_format": "parser", "mutation_strategy": "structured"})));
        assert_eq!(classify("break authentication").1, Some("authentication".into()));
        assert_eq!(classify("crypto weakness").1, Some("cryptography".into()));
        assert_eq!(classify("get RCE"), ("achieve_exploit_type", Some("rce".into()),
            json!({"prioritize_exploitable": true, "deep_analysis": true})));
        assert_eq!(classify("code execution").0, "achieve_exploit_type");
        assert_eq!(classify("maximize coverage"), ("maximize_coverage", None,
            json!({"mutation_strategy": "diverse", "parallel_instances": 4})));
        assert_eq!(classify("explore paths").0, "maximize_coverage");
        assert_eq!(classify("just find bugs"), ("find_any_crash", None, json!({"fast_mode": true})));
    }
}
