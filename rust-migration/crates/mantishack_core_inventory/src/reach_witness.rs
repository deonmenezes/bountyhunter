use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reachability {
    Reachable,
    Unreachable,
    Uncertain,
}

impl Reachability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Unreachable => "unreachable",
            Self::Uncertain => "uncertain",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WitnessKind {
    ModuleAborts,
    LexicalDead,
    BuildExcluded,
    NoPathFromEntry,
    NotCalled,
    HasCaller,
    FrameworkCallable,
    RegisteredViaCall,
    ReachableFromEntry,
    Uncertain,
}

impl WitnessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModuleAborts => "module_aborts",
            Self::LexicalDead => "lexical_dead",
            Self::BuildExcluded => "build_excluded",
            Self::NoPathFromEntry => "no_path_from_entry",
            Self::NotCalled => "not_called",
            Self::HasCaller => "has_caller",
            Self::FrameworkCallable => "framework_callable",
            Self::RegisteredViaCall => "registered_via_call",
            Self::ReachableFromEntry => "reachable_from_entry",
            Self::Uncertain => "uncertain",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Soundness {
    Sound,
    Heuristic,
}

impl Soundness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sound => "sound",
            Self::Heuristic => "heuristic",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Witness {
    pub kind: WitnessKind,
    pub soundness: Soundness,
    pub summary: &'static str,
}

impl Witness {
    pub fn to_priority_reason(&self) -> String {
        format!("reachability:{}", self.kind.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReachabilityVerdict {
    pub status: Reachability,
    pub witness: Witness,
}

impl ReachabilityVerdict {
    pub fn may_suppress(&self, earned_kinds: &HashSet<WitnessKind>) -> bool {
        self.status == Reachability::Unreachable
            && self.witness.soundness == Soundness::Sound
            && earned_kinds.contains(&self.witness.kind)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerdictSpec {
    pub status: Reachability,
    pub kind: WitnessKind,
    pub soundness: Soundness,
    pub earns_suppression: bool,
    pub summary: &'static str,
    pub blocker_template: &'static str,
    pub blocker_detail: &'static str,
    pub prompt_verdict: &'static str,
}

fn specs() -> &'static HashMap<&'static str, VerdictSpec> {
    static SPECS: OnceLock<HashMap<&'static str, VerdictSpec>> = OnceLock::new();
    SPECS.get_or_init(|| {
        HashMap::from([
            (
                "module_aborts",
                VerdictSpec {
                    status: Reachability::Unreachable,
                    kind: WitnessKind::ModuleAborts,
                    soundness: Soundness::Sound,
                    earns_suppression: true,
                    summary: "file aborts on load before this function binds",
                    blocker_template: "reachability:module_aborts — entry function {fq} is in a file whose top-level execution aborts on load ({detail}) before the function binds",
                    blocker_detail: "module_aborts",
                    prompt_verdict: "Verdict: MODULE_ABORTS_ON_LOAD — file aborts at load before this function binds; never importable/callable",
                },
            ),
            (
                "lexical_dead",
                VerdictSpec {
                    status: Reachability::Unreachable,
                    kind: WitnessKind::LexicalDead,
                    soundness: Soundness::Sound,
                    earns_suppression: true,
                    summary: "defined inside an always-false guard",
                    blocker_template: "reachability:lexical_dead — entry function {fq} is defined inside an always-false guard (if False / #[cfg(any())]) and never binds",
                    blocker_detail: "",
                    prompt_verdict: "Verdict: LEXICAL_DEAD — defined inside an always-false guard (if False / #[cfg(any())]); never binds",
                },
            ),
            (
                "build_excluded",
                VerdictSpec {
                    status: Reachability::Unreachable,
                    kind: WitnessKind::BuildExcluded,
                    soundness: Soundness::Heuristic,
                    earns_suppression: false,
                    summary: "translation unit excluded from the build (never compiled)",
                    blocker_template: "reachability:build_excluded — entry function {fq} is in a file excluded from the build ({detail}) and is never compiled",
                    blocker_detail: "build_excluded",
                    prompt_verdict: "Verdict: BUILD_EXCLUDED — file is excluded from the build (e.g. //go:build ignore); never compiled in this configuration",
                },
            ),
            (
                "no_path_from_entry",
                VerdictSpec {
                    status: Reachability::Unreachable,
                    kind: WitnessKind::NoPathFromEntry,
                    soundness: Soundness::Heuristic,
                    earns_suppression: false,
                    summary: "no path from any entry point (orphaned dead-island)",
                    blocker_template: "reachability:no_path_from_entry — entry function {fq} has callers, but none reachable from any entry point (orphaned dead-island)",
                    blocker_detail: "",
                    prompt_verdict: "Verdict: NO_PATH_FROM_ENTRY — has callers, but none reachable from any entry point (orphaned dead-island)",
                },
            ),
            (
                "not_called",
                VerdictSpec {
                    status: Reachability::Unreachable,
                    kind: WitnessKind::NotCalled,
                    soundness: Soundness::Heuristic,
                    earns_suppression: false,
                    summary: "no caller found in non-test project source",
                    blocker_template: "reachability:not_called — entry function {fq} is not called from any non-test project source",
                    blocker_detail: "",
                    prompt_verdict: "",
                },
            ),
            (
                "called",
                simple_spec(
                    Reachability::Reachable,
                    WitnessKind::HasCaller,
                    "called from project source",
                ),
            ),
            (
                "framework_callable",
                simple_spec(
                    Reachability::Reachable,
                    WitnessKind::FrameworkCallable,
                    "registered via framework dispatch",
                ),
            ),
            (
                "registered_via_call",
                simple_spec(
                    Reachability::Reachable,
                    WitnessKind::RegisteredViaCall,
                    "passed as a framework registration argument",
                ),
            ),
            (
                "reachable",
                simple_spec(
                    Reachability::Reachable,
                    WitnessKind::ReachableFromEntry,
                    "reachable from an entry point",
                ),
            ),
            (
                "uncertain",
                simple_spec(
                    Reachability::Uncertain,
                    WitnessKind::Uncertain,
                    "reachability could not be determined",
                ),
            ),
        ])
    })
}

fn simple_spec(
    status: Reachability,
    kind: WitnessKind,
    summary: &'static str,
) -> VerdictSpec {
    VerdictSpec {
        status,
        kind,
        soundness: Soundness::Heuristic,
        earns_suppression: false,
        summary,
        blocker_template: "",
        blocker_detail: "",
        prompt_verdict: "",
    }
}

pub static STRUCTURALLY_SUPPRESSIBLE_KINDS: [WitnessKind; 2] =
    [WitnessKind::ModuleAborts, WitnessKind::LexicalDead];

pub fn verdict_from_classification(verdict: &str) -> ReachabilityVerdict {
    let spec = specs()
        .get(verdict)
        .unwrap_or_else(|| specs().get("uncertain").unwrap());
    ReachabilityVerdict {
        status: spec.status,
        witness: Witness {
            kind: spec.kind,
            soundness: spec.soundness,
            summary: spec.summary,
        },
    }
}

pub fn blocker_for(verdict: &str, fully_qualified: &str, detail: &str) -> Option<String> {
    let spec = specs().get(verdict)?;
    if spec.blocker_template.is_empty() {
        return None;
    }
    Some(
        spec.blocker_template
            .replace("{fq}", fully_qualified)
            .replace("{detail}", detail),
    )
}

pub fn prompt_verdict_for(verdict: &str) -> &'static str {
    specs()
        .get(verdict)
        .map(|spec| spec.prompt_verdict)
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_verdicts() -> [&'static str; 10] {
        [
            "module_aborts",
            "lexical_dead",
            "build_excluded",
            "no_path_from_entry",
            "not_called",
            "called",
            "framework_callable",
            "registered_via_call",
            "reachable",
            "uncertain",
        ]
    }

    #[test]
    fn suppression_chokepoint_matches_python() {
        let empty = HashSet::new();
        for verdict in all_verdicts() {
            assert!(!verdict_from_classification(verdict).may_suppress(&empty));
        }
        let earned = HashSet::from(STRUCTURALLY_SUPPRESSIBLE_KINDS);
        assert!(verdict_from_classification("module_aborts").may_suppress(&earned));
        assert!(verdict_from_classification("lexical_dead").may_suppress(&earned));
        for verdict in ["build_excluded", "no_path_from_entry", "not_called"] {
            let result = verdict_from_classification(verdict);
            assert!(!result.may_suppress(&HashSet::from([result.witness.kind])));
        }
    }

    #[test]
    fn unknown_fails_safe_to_uncertain() {
        let result = verdict_from_classification("something_new");
        assert_eq!(result.status, Reachability::Uncertain);
        assert_eq!(result.witness.kind, WitnessKind::Uncertain);
    }

    #[test]
    fn legacy_priority_reasons_are_stable() {
        assert_eq!(
            verdict_from_classification("module_aborts")
                .witness
                .to_priority_reason(),
            "reachability:module_aborts"
        );
        assert_eq!(
            verdict_from_classification("no_path_from_entry")
                .witness
                .to_priority_reason(),
            "reachability:no_path_from_entry"
        );
    }

    #[test]
    fn blocker_and_prompt_vectors_match_python() {
        let blocker =
            blocker_for("module_aborts", "`m.f`", "raise ImportError").unwrap();
        assert!(blocker.contains("`m.f`"));
        assert!(blocker.contains("raise ImportError"));
        assert_eq!(blocker_for("reachable", "`m.f`", ""), None);
        assert!(prompt_verdict_for("build_excluded").starts_with("Verdict: BUILD_EXCLUDED"));
        assert_eq!(prompt_verdict_for("not_called"), "");
    }
}
