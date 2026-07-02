//! Reachability resolver — Rust port of `core/inventory/reachability.py`
//! (IN PROGRESS).
//!
//! Started with the `Verdict` enum and the pure dict-reading accessors that the
//! `reach_audit` harness consumes (`module_aborts_on_load`, `build_excluded`,
//! `is_lexically_dead`). The full resolver — `function_called`, the adjacency
//! index (`_get_or_build_index`), entry-reachability, and the closures — is a
//! large graph-algorithm layer ported incrementally on top of this foundation.
//!
//! Accessors operate on the inventory as a `serde_json::Value`, matching the
//! Python `Dict[str, Any]` shape produced by the builder.

use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

// Indirection flags that can mask a static "not called" claim (`_MASKING_FLAGS`).
const INDIRECTION_WILDCARD_IMPORT: &str = "wildcard_import";
const MASKING_FLAGS: &[&str] = &[
    "getattr", "importlib", "dunder_import", "wildcard_import",
    "bracket_dispatch", "dynamic_import", "eval", "reflect",
];

/// Verdict plus diagnostic detail. Mirrors `ReachabilityResult`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReachabilityResult {
    pub verdict: Verdict,
    pub evidence: Vec<(String, i64)>,
    pub uncertain_reasons: Vec<(String, String)>,
}

impl ReachabilityResult {
    fn called(evidence: Vec<(String, i64)>, uncertain: Vec<(String, String)>) -> Self {
        Self { verdict: Verdict::Called, evidence, uncertain_reasons: uncertain }
    }
    fn uncertain(uncertain: Vec<(String, String)>) -> Self {
        Self { verdict: Verdict::Uncertain, evidence: Vec::new(), uncertain_reasons: uncertain }
    }
    fn not_called() -> Self {
        Self { verdict: Verdict::NotCalled, evidence: Vec::new(), uncertain_reasons: Vec::new() }
    }
}

/// A project-defined function. Identity is `(file_path, name, line)` — the line
/// disambiguates same-name overloads / nested defs / methods of different
/// classes in one file. Mirrors `InternalFunction`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InternalFunction {
    pub file_path: String,
    pub name: String,
    pub line: i64,
}

impl InternalFunction {
    pub fn new(file_path: impl Into<String>, name: impl Into<String>, line: i64) -> Self {
        Self { file_path: file_path.into(), name: name.into(), line }
    }
    /// `file_path:name@line` (Python `__str__`).
    pub fn display(&self) -> String {
        format!("{}:{}@{}", self.file_path, self.name, self.line)
    }
}

/// Python truthiness for a JSON value (for the `x or []` fallbacks).
fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Linear scan of the inventory's files for a path match (`_find_file_record`).
fn find_file_record<'a>(inventory: &'a Value, path: &str) -> Option<&'a Value> {
    inventory.get("files")?.as_array()?.iter().find(|fr| {
        fr.get("path").and_then(Value::as_str) == Some(path)
    })
}

/// Return the project-internal function whose body contains `line` in
/// `file_path`, or `None` if the line is at module scope (`enclosing_function`).
/// Innermost (largest `line_start` ≤ `line`) match wins.
pub fn enclosing_function(inventory: &Value, file_path: &str, line: i64) -> Option<InternalFunction> {
    let file_record = find_file_record(inventory, file_path)?;
    // `items = fr.get("items") or []; if not isinstance(items, list): return None`
    let items: &[Value] = match file_record.get("items") {
        Some(Value::Array(a)) => a.as_slice(),
        Some(v) if is_truthy(v) => return None, // truthy non-list
        _ => &[],                               // null / absent / falsy -> empty
    };

    let mut best: Option<(i64, String)> = None; // (line_start, name)
    for item in items {
        let Some(obj) = item.as_object() else { continue };
        // kind must be absent, null, or "function".
        match obj.get("kind") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if s == "function" => {}
            _ => continue,
        }
        let Some(line_start) = obj.get("line_start").and_then(Value::as_i64) else { continue };
        if line_start <= 0 || line_start > line {
            continue;
        }
        // Missing/negative line_end -> open-ended range.
        if let Some(line_end) = obj.get("line_end").and_then(Value::as_i64) {
            if line_end >= 0 && line_end < line {
                continue;
            }
        }
        if best.as_ref().map_or(true, |(bls, _)| line_start > *bls) {
            let name = obj.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            best = Some((line_start, name));
        }
    }

    let (line_start, name) = best?;
    if name.is_empty() {
        return None;
    }
    Some(InternalFunction::new(file_path, name, line_start))
}

/// Split a `"path:line"` evidence string into `(path, line)`
/// (`parse_evidence_entry`); `(None, 0)` for malformed inputs. Splits on the
/// LAST colon so Windows drive paths / IPv6 fragments survive.
pub fn parse_evidence_entry(entry: &str) -> (Option<String>, i64) {
    let Some((path, line_str)) = entry.rsplit_once(':') else { return (None, 0) };
    if path.is_empty() || line_str.is_empty() {
        return (None, 0);
    }
    match line_str.trim().parse::<i64>() {
        Ok(line) => (Some(path.to_string()), line),
        Err(_) => (None, 0),
    }
}

#[cfg(test)]
mod enclosing_and_evidence_tests {
    use super::*;
    use serde_json::json;

    fn inv() -> Value {
        json!({"files": [{"path": "a.py", "items": [
            {"kind": "function", "name": "outer", "line_start": 1, "line_end": 20},
            {"kind": "function", "name": "inner", "line_start": 5, "line_end": 10},
            {"kind": "function", "name": "noend", "line_start": 25},
            {"kind": "class", "name": "C", "line_start": 30, "line_end": 40},
        ]}]})
    }

    fn ef(line: i64) -> Option<(String, i64)> {
        enclosing_function(&inv(), "a.py", line).map(|f| (f.name, f.line))
    }

    #[test]
    fn enclosing_innermost_and_open_ended() {
        assert_eq!(ef(7), Some(("inner".into(), 5))); // innermost def wins
        assert_eq!(ef(15), Some(("outer".into(), 1)));
        assert_eq!(ef(3), Some(("outer".into(), 1)));
        // Open-ended def (no line_end) captures everything at/after its start,
        // including a range a `class` (excluded) would otherwise cover.
        assert_eq!(ef(25), Some(("noend".into(), 25)));
        assert_eq!(ef(35), Some(("noend".into(), 25)));
        assert_eq!(ef(50), Some(("noend".into(), 25)));
        // No matching file.
        assert_eq!(enclosing_function(&inv(), "b.py", 1), None);
    }

    #[test]
    fn parse_evidence() {
        assert_eq!(parse_evidence_entry("a.py:10"), (Some("a.py".into()), 10));
        assert_eq!(parse_evidence_entry("C:\\x:42"), (Some("C:\\x".into()), 42)); // last colon
        assert_eq!(parse_evidence_entry("nocolon"), (None, 0));
        assert_eq!(parse_evidence_entry(":10"), (None, 0)); // empty path
        assert_eq!(parse_evidence_entry("a.py:"), (None, 0)); // empty line
        assert_eq!(parse_evidence_entry("a.py:abc"), (None, 0)); // non-numeric
        assert_eq!(parse_evidence_entry("a.py:0"), (Some("a.py".into()), 0));
        assert_eq!(parse_evidence_entry("a.py: 5 "), (Some("a.py".into()), 5)); // int() strips ws
    }
}

/// A dep-defined function referenced by qualified name. Mirrors `ExternalFunction`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExternalFunction {
    pub qualified_name: String,
}

fn test_file_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(^|/)(tests?/.*|test_[^/]+\.py|[^/]+_test\.py|conftest\.py)$").unwrap()
    })
}

/// Conventional test-file detection (`tests?/…`, `test_*.py`, `*_test.py`,
/// `conftest.py`). Port of `_is_test_file` (os.sep is `/` on the oracle host).
pub fn is_test_file(path: &str) -> bool {
    test_file_re().is_match(path)
}

/// Universal file-path -> module conversion (`_file_path_to_module`):
/// `c/heartbeat.c` -> `c.heartbeat`. `None` for extensionless paths.
pub fn file_path_to_module(rel_path: &str) -> Option<String> {
    if rel_path.is_empty() {
        return None;
    }
    let normalized = rel_path.replace('\\', "/");
    let mut parts: Vec<String> = normalized
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .map(str::to_string)
        .collect();
    let last = parts.last()?.clone();
    // PurePosixPath.suffix: a `.` at index i with 0 < i < len-1.
    let dot = last.rfind('.');
    let stem = match dot {
        Some(i) if i > 0 && i < last.len() - 1 => last[..i].to_string(),
        _ => return None,
    };
    *parts.last_mut().unwrap() = stem;
    Some(parts.join("."))
}

/// Candidate `<file_module>.<class>.<fn>` forms for languages where the file is
/// the module (`_path_derived_module`). One or two candidates (the raw form +
/// an `src/`-stripped form). Empty when the extension isn't recognised.
pub fn path_derived_module(file_path: &str, class_name: &str, fn_name: &str) -> Vec<String> {
    const SUFFIXES: &[&str] = &[".pyi", ".py", ".tsx", ".jsx", ".mjs", ".cjs", ".ts", ".js", ".rb"];
    let mut base = file_path;
    let mut matched = false;
    for suf in SUFFIXES {
        if base.ends_with(suf) {
            base = &base[..base.len() - suf.len()];
            matched = true;
            break;
        }
    }
    if !matched {
        return Vec::new();
    }
    let mut base = base.to_string();
    if let Some(stripped) = base.strip_suffix("/__init__") {
        base = stripped.to_string();
    } else if let Some(stripped) = base.strip_suffix("/index") {
        base = stripped.to_string();
    }
    if base.is_empty() {
        return Vec::new();
    }
    let mut out = vec![format!("{}.{}.{}", base.replace('/', "."), class_name, fn_name)];
    if let Some(stripped) = base.strip_prefix("src/") {
        if !stripped.is_empty() {
            out.push(format!("{}.{}.{}", stripped.replace('/', "."), class_name, fn_name));
        }
    }
    out
}

/// Reachability verdict for a queried qualified name (`Verdict`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Called,
    NotCalled,
    Uncertain,
}

impl Verdict {
    /// The lowercase string form, matching the Python `str` enum values.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Called => "called",
            Verdict::NotCalled => "not_called",
            Verdict::Uncertain => "uncertain",
        }
    }
}

fn norm(p: &str) -> String {
    p.replace('\\', "/")
}

/// First file record whose (slash-normalised) `path` equals `file_path`.
fn find_file<'a>(inventory: &'a Value, file_path: &str) -> Option<&'a Value> {
    let target = norm(file_path);
    inventory.get("files")?.as_array()?.iter().find(|fr| {
        fr.get("path").and_then(Value::as_str).map(norm).as_deref() == Some(target.as_str())
    })
}

/// The module-load-abort record for `file_path` (with `line`/`summary`) if the
/// builder detected an unconditional top-of-module abort, else `None`.
/// Path-keyed lookup, no index build.
pub fn module_aborts_on_load(inventory: &Value, file_path: &str) -> Option<Value> {
    if file_path.is_empty() {
        return None;
    }
    let fr = find_file(inventory, file_path)?;
    match fr.get("module_aborts_on_load") {
        Some(v) if v.is_object() => Some(v.clone()),
        _ => None,
    }
}

/// The build-exclusion record for `file_path` if the builder detected the file
/// is never compiled (e.g. Go `//go:build ignore`), else `None`.
pub fn build_excluded(inventory: &Value, file_path: &str) -> Option<Value> {
    if file_path.is_empty() {
        return None;
    }
    let fr = find_file(inventory, file_path)?;
    match fr.get("build_excluded") {
        Some(v) if v.is_object() => Some(v.clone()),
        _ => None,
    }
}

/// True iff `name` (at `line`, when `line > 0`) is defined inside a lexically
/// dead scope (`lexical_dead=True` on the item). With `line == 0`, matches by
/// name within the file (first hit wins). False-negative-safe: returns `false`
/// when the file or function isn't found.
pub fn is_lexically_dead(inventory: &Value, file_path: &str, name: &str, line: i64) -> bool {
    if file_path.is_empty() || name.is_empty() {
        return false;
    }
    let Some(fr) = find_file(inventory, file_path) else { return false };
    let Some(items) = fr.get("items").and_then(Value::as_array) else { return false };
    for item in items {
        if item.get("name").and_then(Value::as_str) != Some(name) {
            continue;
        }
        if line != 0 && item.get("line_start").and_then(Value::as_i64) != Some(line) {
            continue;
        }
        return item.get("lexical_dead").and_then(Value::as_bool).unwrap_or(false);
    }
    false
}

// ---------------------------------------------------------------------------
// Framework-entry detection — per-language metadata checks feeding the entry
// set (`_item_is_entry` + `_java/_ts/_csharp/_ruby_framework_entry`).
// ---------------------------------------------------------------------------

const JAVA_SERVLET_METHODS: &[&str] = &[
    "doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions", "doTrace",
    "service", "doFilter", "init", "destroy",
];
const JAVA_METHOD_DISPATCH_ANNOTATIONS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "Path",
    "RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping",
    "PatchMapping", "Bean", "PostConstruct", "PreDestroy", "EventListener",
    "Scheduled", "KafkaListener", "RabbitListener", "JmsListener", "MessageMapping",
    "SubscribeMapping", "StreamListener", "PrePersist", "PostPersist", "PreUpdate",
    "PostUpdate", "PreRemove", "PostRemove", "PostLoad", "XmlElement",
    "XmlAttribute", "XmlValue", "XmlElementWrapper",
];
const JAVA_CLASS_STEREOTYPES: &[&str] = &[
    "Component", "Service", "Repository", "Controller", "RestController",
    "Configuration", "ControllerAdvice", "RestControllerAdvice", "Entity",
    "Embeddable", "MappedSuperclass", "XmlRootElement", "XmlType",
];
const JAVA_FRAMEWORK_BASES: &[&str] = &[
    "Repository", "CrudRepository", "JpaRepository", "PagingAndSortingRepository",
    "ReactiveCrudRepository", "MongoRepository", "JpaSpecificationExecutor",
    "Validator", "RuntimeHintsRegistrar", "Filter", "HandlerInterceptor",
    "Converter", "Formatter", "ApplicationRunner", "CommandLineRunner",
    "ApplicationListener", "InitializingBean", "DisposableBean",
];
const TS_METHOD_DISPATCH_DECORATORS: &[&str] = &[
    "Get", "Post", "Put", "Delete", "Patch", "Options", "Head", "All", "Search",
    "MessagePattern", "EventPattern", "SubscribeMessage", "Cron", "Interval",
    "Timeout", "Query", "Mutation", "Subscription", "ResolveField",
    "ResolveProperty", "FieldResolver",
];
const TS_CLASS_STEREOTYPE_DECORATORS: &[&str] = &[
    "Controller", "Injectable", "Module", "Resolver", "Catch", "WebSocketGateway",
    "Gateway", "Component", "Directive", "Pipe", "NgModule", "Entity",
    "ViewEntity", "ChildEntity",
];
const CSHARP_METHOD_DISPATCH_ATTRS: &[&str] = &[
    "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "HttpHead",
    "HttpOptions", "Route", "AcceptVerbs",
];
const CSHARP_CLASS_STEREOTYPE_ATTRS: &[&str] = &["ApiController", "Controller", "Route"];
const RUBY_FRAMEWORK_BASES: &[&str] = &[
    "ApplicationController", "ActionController::Base", "ActionController::API",
    "ApplicationJob", "ActiveJob::Base", "ApplicationMailer", "ActionMailer::Base",
    "ApplicationCable::Channel", "ActionCable::Channel::Base",
];

/// `@org.spring..RequestMapping("/x")` -> `RequestMapping` (`_annotation_tail`).
fn annotation_tail(a: &str) -> &str {
    let before_paren = a.split('(').next().unwrap_or("").trim();
    before_paren.rsplit('.').next().unwrap_or("").trim_start_matches('@')
}

fn str_list<'a>(item: &'a Value, key: &str) -> Vec<&'a str> {
    item.get("metadata")
        .and_then(|m| m.get(key))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn visibility_has_public(item: &Value) -> bool {
    item.get("metadata")
        .and_then(|m| m.get("visibility"))
        .and_then(Value::as_str)
        .map(|v| v.split_whitespace().any(|t| t == "public"))
        .unwrap_or(false)
}

fn any_tail_in(attrs: &[&str], set: &[&str]) -> bool {
    attrs.iter().any(|a| set.contains(&annotation_tail(a)))
}

fn java_framework_entry(name: &str, item: &Value) -> bool {
    if JAVA_SERVLET_METHODS.contains(&name) {
        return true;
    }
    if any_tail_in(&str_list(item, "attributes"), JAVA_METHOD_DISPATCH_ANNOTATIONS) {
        return true;
    }
    let class_attrs = str_list(item, "class_attributes");
    if any_tail_in(&class_attrs, JAVA_FRAMEWORK_BASES) {
        return true;
    }
    visibility_has_public(item) && any_tail_in(&class_attrs, JAVA_CLASS_STEREOTYPES)
}

fn ts_framework_entry(item: &Value) -> bool {
    if any_tail_in(&str_list(item, "attributes"), TS_METHOD_DISPATCH_DECORATORS) {
        return true;
    }
    visibility_has_public(item) && any_tail_in(&str_list(item, "class_attributes"), TS_CLASS_STEREOTYPE_DECORATORS)
}

fn csharp_framework_entry(item: &Value) -> bool {
    if any_tail_in(&str_list(item, "attributes"), CSHARP_METHOD_DISPATCH_ATTRS) {
        return true;
    }
    visibility_has_public(item) && any_tail_in(&str_list(item, "class_attributes"), CSHARP_CLASS_STEREOTYPE_ATTRS)
}

fn ruby_framework_entry(item: &Value) -> bool {
    // Raw base names (not tail-stripped), plus the `*Controller` convention.
    str_list(item, "class_attributes")
        .iter()
        .any(|base| RUBY_FRAMEWORK_BASES.contains(base) || base.ends_with("Controller"))
}

#[derive(Default)]
struct Profile {
    visibility_entry: &'static str,
    has_go_init: bool,
    has_java_web: bool,
    has_ts_framework: bool,
    has_csharp_framework: bool,
    has_ruby_framework: bool,
}

fn profile(language: &str) -> Profile {
    match language {
        "c" | "cpp" => Profile { visibility_entry: "non_static", ..Default::default() },
        "go" => Profile { visibility_entry: "go_exported", has_go_init: true, ..Default::default() },
        "rust" => Profile { visibility_entry: "rust_pub", ..Default::default() },
        "java" => Profile { has_java_web: true, ..Default::default() },
        "typescript" | "tsx" => Profile { has_ts_framework: true, ..Default::default() },
        "ruby" => Profile { has_ruby_framework: true, ..Default::default() },
        "csharp" => Profile { has_csharp_framework: true, ..Default::default() },
        _ => Profile::default(), // python, javascript, php, unknown
    }
}

/// Is this inventory item an externally-invocable entry point under its
/// language's linkage/visibility model + framework dispatch? Port of
/// `_item_is_entry`. (Feeds the adjacency index's entry set.)
pub fn item_is_entry(item: &Value, language: &str) -> bool {
    let name = item.get("name").and_then(Value::as_str).unwrap_or("");
    if name == "main" {
        return true;
    }
    let p = profile(language);
    if p.has_go_init && name == "init" {
        return true;
    }
    if p.has_java_web && java_framework_entry(name, item) {
        return true;
    }
    if p.has_ts_framework && ts_framework_entry(item) {
        return true;
    }
    if p.has_csharp_framework && csharp_framework_entry(item) {
        return true;
    }
    if p.has_ruby_framework && ruby_framework_entry(item) {
        return true;
    }
    if p.visibility_entry.is_empty() {
        return false;
    }
    let vis = item.get("metadata").and_then(|m| m.get("visibility")).and_then(Value::as_str);
    match p.visibility_entry {
        "non_static" => vis != Some("static"),
        "go_exported" => vis == Some("exported") || name.chars().next().is_some_and(char::is_uppercase),
        "rust_pub" => matches!(vis, Some("public") | Some("pub")),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// function_called — "is this dotted dep name called anywhere in the project?"
// Port of _build_function_called_index + _resolves_to + _wildcard_could_provide
// + function_called. The id()-keyed index cache is a perf optimisation; here
// the index is rebuilt per call (semantics-identical).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FunctionCalledIndex {
    files_by_token: HashMap<String, Vec<usize>>,
    files_with_non_wildcard_masking: Vec<usize>,
    files_with_wildcard_import: Vec<usize>,
    macro_targets: HashMap<String, Vec<String>>,
}

/// A call_graph field that is present and a non-empty object (Python `if not cg`).
fn nonempty_cg(fr: &Value) -> Option<&Value> {
    match fr.get("call_graph") {
        Some(c) if c.as_object().is_some_and(|o| !o.is_empty()) => Some(c),
        _ => None,
    }
}

fn str_array<'a>(v: &'a Value, key: &str) -> Vec<&'a str> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn chain_of(call: &Value) -> Vec<String> {
    call.get("chain")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

fn build_function_called_index(inventory: &Value) -> FunctionCalledIndex {
    let empty = Vec::new();
    let files = inventory.get("files").and_then(Value::as_array).unwrap_or(&empty);
    let mut files_by_token: HashMap<String, BTreeSet<usize>> = HashMap::new();
    let mut non_wildcard: BTreeSet<usize> = BTreeSet::new();
    let mut wildcard: BTreeSet<usize> = BTreeSet::new();
    let mut macro_targets: HashMap<String, BTreeSet<String>> = HashMap::new();

    fn add(map: &mut HashMap<String, BTreeSet<usize>>, token: &str, i: usize) {
        if !token.is_empty() {
            map.entry(token.to_string()).or_default().insert(i);
        }
    }

    for (i, fr) in files.iter().enumerate() {
        if !fr.is_object() {
            continue;
        }
        let Some(cg) = nonempty_cg(fr) else { continue };
        // Imports: index every dotted prefix of each bound + its tail.
        if let Some(imports) = cg.get("imports").and_then(Value::as_object) {
            for bound in imports.values() {
                let Some(bound) = bound.as_str() else { continue };
                if bound.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = bound.split('.').collect();
                for k in 1..=parts.len() {
                    add(&mut files_by_token, &parts[..k].join("."), i);
                }
                add(&mut files_by_token, parts[parts.len() - 1], i);
            }
        }
        // Calls: chain tail + fully-qualified dotted chain.
        if let Some(calls) = cg.get("calls").and_then(Value::as_array) {
            for call in calls {
                let chain = chain_of(call);
                if chain.is_empty() {
                    continue;
                }
                add(&mut files_by_token, &chain[chain.len() - 1], i);
                if chain.len() >= 2 {
                    add(&mut files_by_token, &chain.join("."), i);
                }
            }
        }
        // getattr literals.
        for name in str_array(cg, "getattr_targets") {
            add(&mut files_by_token, name, i);
        }
        // Indirection flags split into the two buckets.
        let flags: BTreeSet<&str> = str_array(cg, "indirection").into_iter().collect();
        let has_non_wildcard = flags
            .iter()
            .any(|f| MASKING_FLAGS.contains(f) && *f != INDIRECTION_WILDCARD_IMPORT);
        if has_non_wildcard {
            non_wildcard.insert(i);
        }
        if flags.contains(INDIRECTION_WILDCARD_IMPORT) {
            wildcard.insert(i);
        }
        // Function-like-macro call targets (C/C++).
        let mpath = fr.get("path").and_then(Value::as_str).unwrap_or("").to_string();
        for name in str_array(cg, "macro_call_targets") {
            macro_targets.entry(name.to_string()).or_default().insert(mpath.clone());
        }
    }

    FunctionCalledIndex {
        files_by_token: files_by_token.into_iter().map(|(k, v)| (k, v.into_iter().collect())).collect(),
        files_with_non_wildcard_masking: non_wildcard.into_iter().collect(),
        files_with_wildcard_import: wildcard.into_iter().collect(),
        macro_targets: macro_targets.into_iter().map(|(k, v)| (k, v.into_iter().collect())).collect(),
    }
}

fn resolves_to(chain: &[String], imports: &Map<String, Value>, target_module: &str, target_func: &str) -> bool {
    if chain.len() == 1 {
        return imports.get(&chain[0]).and_then(Value::as_str)
            == Some(format!("{target_module}.{target_func}").as_str());
    }
    let Some(bound) = imports.get(&chain[0]).and_then(Value::as_str) else { return false };
    let middle = chain[1..chain.len() - 1].join(".");
    let resolved_module = if middle.is_empty() { bound.to_string() } else { format!("{bound}.{middle}") };
    resolved_module == target_module && chain[chain.len() - 1] == target_func
}

fn wildcard_could_provide(imports: &Map<String, Value>, target_module: &str) -> bool {
    let target_root = target_module.split('.').next().unwrap_or("");
    imports.values().any(|q| {
        q.as_str().is_some_and(|s| s.split('.').next().unwrap_or("") == target_root)
    })
}

fn call_line(call: &Value) -> i64 {
    call.get("line").and_then(Value::as_i64).unwrap_or(0)
}

/// The `language` of the file record whose path matches `file_path` (`_file_language`).
pub fn file_language(inventory: &Value, file_path: &str) -> Option<String> {
    find_file(inventory, file_path)
        .and_then(|fr| fr.get("language"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// True iff `file_path`'s call_graph carries any masking indirection flag or a
/// function-like-macro call target (`_file_has_masking`).
pub fn file_has_masking(inventory: &Value, file_path: &str) -> bool {
    let Some(fr) = find_file(inventory, file_path) else { return false };
    let Some(cg) = fr.get("call_graph") else { return false };
    let flags: Vec<&str> = str_array(cg, "indirection");
    if flags.iter().any(|f| MASKING_FLAGS.contains(f)) {
        return true;
    }
    cg.get("macro_call_targets")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty())
}

/// Determine whether `qualified_name` (dotted) is called by the project.
/// `Err` mirrors the Python `ValueError` for a non-dotted name.
pub fn function_called(
    inventory: &Value,
    qualified_name: &str,
    exclude_test_files: bool,
) -> Result<ReachabilityResult, String> {
    if qualified_name.is_empty() || !qualified_name.contains('.') {
        return Err(format!("qualified_name must be dotted (module.function); got {qualified_name:?}"));
    }
    let target_parts: Vec<&str> = qualified_name.split('.').collect();
    let target_func = target_parts[target_parts.len() - 1];
    let target_module = target_parts[..target_parts.len() - 1].join(".");
    let target_dot_func = format!("{target_module}.{target_func}");
    let target_module_dot = format!("{target_module}.");

    let mut evidence: Vec<(String, i64)> = Vec::new();
    let mut uncertain_reasons: Vec<(String, String)> = Vec::new();

    let empty = Vec::new();
    let files = inventory.get("files").and_then(Value::as_array).unwrap_or(&empty);
    let index = build_function_called_index(inventory);

    let mut candidate_idx: BTreeSet<usize> = BTreeSet::new();
    for tok in [target_module.as_str(), target_func, qualified_name] {
        if let Some(bucket) = index.files_by_token.get(tok) {
            candidate_idx.extend(bucket.iter().copied());
        }
    }
    candidate_idx.extend(index.files_with_non_wildcard_masking.iter().copied());
    candidate_idx.extend(index.files_with_wildcard_import.iter().copied());

    for &i in &candidate_idx {
        let Some(file_record) = files.get(i) else { continue };
        if !file_record.is_object() {
            continue;
        }
        let path = file_record.get("path").and_then(Value::as_str).unwrap_or("");
        if exclude_test_files && is_test_file(path) {
            continue;
        }
        let Some(cg) = nonempty_cg(file_record) else { continue };
        let empty_map = Map::new();
        let imports = cg.get("imports").and_then(Value::as_object).unwrap_or(&empty_map);
        let calls = cg.get("calls").and_then(Value::as_array).cloned().unwrap_or_default();
        let flags: BTreeSet<&str> = str_array(cg, "indirection").into_iter().collect();
        let getattr_targets: BTreeSet<&str> = str_array(cg, "getattr_targets").into_iter().collect();

        // Fast-path skip: does any import bind to the target module?
        let target_in_imports = imports.values().any(|b| {
            b.as_str().is_some_and(|s| s == target_module || s == target_dot_func || s.starts_with(&target_module_dot))
        });

        let mut file_has_evidence = false;
        if target_in_imports {
            for call in &calls {
                let chain = chain_of(call);
                if chain.is_empty() {
                    continue;
                }
                if resolves_to(&chain, imports, &target_module, target_func) {
                    file_has_evidence = true;
                    evidence.push((path.to_string(), call_line(call)));
                }
            }
        }

        // receiver_class fast-path.
        if !file_has_evidence {
            let file_pkg = cg.get("package_name").and_then(Value::as_str);
            for call in &calls {
                let chain = chain_of(call);
                if chain.is_empty() || chain[chain.len() - 1] != target_func {
                    continue;
                }
                let Some(rc) = call.get("receiver_class").and_then(Value::as_str) else { continue };
                let candidates: Vec<String> = match file_pkg {
                    Some(pkg) => vec![format!("{pkg}.{rc}.{target_func}")],
                    None => path_derived_module(path, rc, target_func),
                };
                if candidates.iter().any(|c| c == qualified_name) {
                    file_has_evidence = true;
                    evidence.push((path.to_string(), call_line(call)));
                }
            }
        }

        // Fully-qualified-call fast-path.
        if !file_has_evidence {
            for call in &calls {
                let chain = chain_of(call);
                if chain.len() >= 2 && chain.join(".") == qualified_name {
                    file_has_evidence = true;
                    evidence.push((path.to_string(), call_line(call)));
                }
            }
        }

        // Same-file bare-name fast-path.
        if !file_has_evidence && file_path_to_module(path).as_deref() == Some(target_module.as_str()) {
            for call in &calls {
                let chain = chain_of(call);
                if chain.len() != 1 || chain[0] != target_func {
                    continue;
                }
                if imports.contains_key(&chain[0]) {
                    continue;
                }
                file_has_evidence = true;
                evidence.push((path.to_string(), call_line(call)));
                break;
            }
        }

        if file_has_evidence {
            continue;
        }

        // Non-wildcard masking branch (lazy file_mentions_tail).
        let non_wildcard_flags: BTreeSet<&str> = flags
            .iter()
            .copied()
            .filter(|f| MASKING_FLAGS.contains(f) && *f != INDIRECTION_WILDCARD_IMPORT)
            .collect();
        if !non_wildcard_flags.is_empty() {
            let file_mentions_tail = getattr_targets.contains(target_func)
                || calls.iter().any(|c| {
                    let ch = chain_of(c);
                    !ch.is_empty() && ch[ch.len() - 1] == target_func
                })
                || imports.values().any(|q| {
                    q.as_str().is_some_and(|s| s.rsplit('.').next().unwrap_or("") == target_func)
                });
            if file_mentions_tail {
                for flag in &non_wildcard_flags {
                    uncertain_reasons.push((path.to_string(), flag.to_string()));
                }
            }
        }

        if flags.contains(INDIRECTION_WILDCARD_IMPORT) && wildcard_could_provide(imports, &target_module) {
            uncertain_reasons.push((path.to_string(), INDIRECTION_WILDCARD_IMPORT.to_string()));
        }
    }

    // Function-like-macro masking (C/C++).
    if let Some(mpaths) = index.macro_targets.get(target_func) {
        for mpath in mpaths {
            if exclude_test_files && is_test_file(mpath) {
                continue;
            }
            uncertain_reasons.push((mpath.clone(), "func_like_macro".to_string()));
        }
    }

    if !evidence.is_empty() {
        return Ok(ReachabilityResult::called(evidence, uncertain_reasons));
    }
    if !uncertain_reasons.is_empty() {
        return Ok(ReachabilityResult::uncertain(uncertain_reasons));
    }
    Ok(ReachabilityResult::not_called())
}

// ---------------------------------------------------------------------------
// _AdjacencyIndex — the per-inventory call-graph index that callers_of /
// callees_of / call_lines_of / entry-reachability / the closures consume.
// Port of _AdjacencyIndex + _get_or_build_index + its resolution helpers. The
// id()-keyed + on-disk caches are perf only; this rebuilds per call.
// ---------------------------------------------------------------------------

use std::collections::HashSet;

/// A call-graph node: a project function or a dep-qualified name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FunctionId {
    Internal(InternalFunction),
    External(ExternalFunction),
}

/// 1-hop callers of a target (`CallersResult`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallersResult {
    pub definitive: Vec<InternalFunction>,
    pub uncertain: Vec<InternalFunction>,
    pub method_match_overinclusive: Vec<InternalFunction>,
}

/// 1-hop callees of an internal source (`CalleesResult`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CalleesResult {
    pub definitive: Vec<FunctionId>,
    pub uncertain: Vec<String>,
    pub has_method_dispatch: bool,
}

const FRAMEWORK_DISPATCH_TAILS: &[&str] = &[
    "route", "get", "post", "put", "patch", "delete", "head", "options",
    "endpoint", "websocket", "errorhandler", "exception_handler",
    "before_request", "after_request", "teardown_request", "middleware",
    "on_event", "command", "group", "callback", "task", "periodic_task",
    "shared_task", "actor", "receiver", "connect", "listener", "subscriber",
    "subscribe", "on", "emit_handler", "register", "hook", "provider",
    "consumer", "handler", "dispatch", "rule", "fixture", "parametrize", "mark",
    "query", "mutation", "subscription", "field", "resolver", "session",
    "module_task",
];
const FRAMEWORK_DISPATCH_NAKED_NAMES: &[&str] = &["receiver", "shared_task", "periodic_task", "actor"];
const FRAMEWORK_REGISTRATION_TAILS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "all", "use",
    "route", "param", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
    "Any", "Use", "Group", "Static", "Get", "Post", "Put", "Patch", "Delete",
    "Head", "Options", "Method", "MethodFunc", "Mount", "Handle", "HandleFunc",
];
const SAFE_BUILTIN_BASES: &[&str] = &[
    "object", "Exception", "BaseException", "ValueError", "TypeError",
    "KeyError", "IndexError", "RuntimeError", "OSError", "IOError",
    "FileNotFoundError", "NotImplementedError", "StopIteration", "AttributeError",
    "ImportError", "ModuleNotFoundError", "UnicodeError", "ZeroDivisionError",
    "ArithmeticError", "LookupError", "MemoryError", "OverflowError", "NameError",
    "ReferenceError", "SyntaxError", "SystemError", "GeneratorExit",
    "KeyboardInterrupt", "SystemExit", "Warning", "Enum", "IntEnum", "Flag",
    "IntFlag", "StrEnum", "NamedTuple", "Protocol", "ABCMeta", "ABC", "tuple",
    "list", "dict", "set", "frozenset", "str", "bytes", "bytearray", "int",
    "float", "bool", "complex",
];

#[derive(Default)]
pub struct AdjacencyIndex {
    forward: HashMap<InternalFunction, HashSet<FunctionId>>,
    reverse: HashMap<FunctionId, HashSet<InternalFunction>>,
    uncertain_callers_by_tail: HashMap<String, HashSet<(InternalFunction, String)>>,
    method_match: HashMap<String, HashSet<(InternalFunction, Option<String>)>>,
    uncertain_callees: HashMap<InternalFunction, HashSet<String>>,
    has_method_dispatch: HashMap<InternalFunction, bool>,
    definitions: HashMap<(String, String), HashSet<InternalFunction>>,
    class_of_method: HashMap<InternalFunction, String>,
    class_bases: HashMap<(String, String), Vec<String>>,
    override_methods: HashSet<(String, String)>,
    framework_callable: HashSet<InternalFunction>,
    framework_registered: HashSet<InternalFunction>,
    qualified_to_internal: HashMap<String, InternalFunction>,
    call_lines: HashMap<(InternalFunction, FunctionId), Vec<i64>>,
    test_paths: HashSet<String>,
}

fn decorators_indicate_framework_dispatch(decorators: &Value) -> bool {
    let Some(arr) = decorators.as_array() else { return false };
    for chain in arr {
        let Some(parts) = chain.as_array() else { continue };
        if parts.is_empty() {
            continue;
        }
        let tail = parts[parts.len() - 1].as_str().unwrap_or("");
        if parts.len() >= 2 && FRAMEWORK_DISPATCH_TAILS.contains(&tail) {
            return true;
        }
        if parts.len() == 1 && FRAMEWORK_DISPATCH_NAKED_NAMES.contains(&tail) {
            return true;
        }
    }
    false
}

fn candidate_qualified_names(file_path: &str, fn_name: &str, package_name: Option<&str>, class_name: Option<&str>) -> Vec<String> {
    let mut candidates = Vec::new();
    let class_required = file_path.ends_with(".java");
    if let (Some(pkg), Some(cls)) = (package_name, class_name) {
        candidates.push(format!("{pkg}.{cls}.{fn_name}"));
    }
    // Module-level form: emitted iff there's a package and the language isn't
    // class-required (Java methods only resolve class-qualified).
    if let Some(pkg) = package_name {
        if !class_required {
            candidates.push(format!("{pkg}.{fn_name}"));
        }
    }
    if file_path.ends_with(".py") || file_path.ends_with(".pyi") {
        let mut base = file_path;
        for suf in [".pyi", ".py"] {
            if let Some(s) = base.strip_suffix(suf) {
                base = s;
                break;
            }
        }
        let base = base.strip_suffix("/__init__").unwrap_or(base);
        if !base.is_empty() {
            candidates.push(format!("{}.{fn_name}", base.replace('/', ".")));
        }
        if let Some(stripped) = base.strip_prefix("src/") {
            if !stripped.is_empty() {
                candidates.push(format!("{}.{fn_name}", stripped.replace('/', ".")));
            }
        }
    }
    if [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".rb"].iter().any(|e| file_path.ends_with(e)) {
        let mut base = file_path;
        for suf in [".tsx", ".mjs", ".cjs", ".jsx", ".js", ".ts", ".rb"] {
            if let Some(s) = base.strip_suffix(suf) {
                base = s;
                break;
            }
        }
        let base = base.strip_suffix("/index").unwrap_or(base);
        if !base.is_empty() {
            let module_form = base.replace('/', ".");
            if let Some(cls) = class_name {
                candidates.push(format!("{module_form}.{cls}.{fn_name}"));
            }
            candidates.push(format!("{module_form}.{fn_name}"));
        }
    }
    candidates
}

fn resolve_callee_chain(chain: &[String], imports: &Map<String, Value>) -> Option<ExternalFunction> {
    if chain.is_empty() {
        return None;
    }
    if chain.len() == 1 {
        let bound = imports.get(&chain[0]).and_then(Value::as_str)?;
        return Some(ExternalFunction { qualified_name: bound.to_string() });
    }
    let bound = imports.get(&chain[0]).and_then(Value::as_str)?;
    let middle = chain[1..chain.len() - 1].join(".");
    let qualified = if middle.is_empty() {
        format!("{bound}.{}", chain[chain.len() - 1])
    } else {
        format!("{bound}.{middle}.{}", chain[chain.len() - 1])
    };
    Some(ExternalFunction { qualified_name: qualified })
}

fn resolve_caller(idx: &AdjacencyIndex, file_path: &str, caller_name: Option<&str>, call_line: i64) -> Option<InternalFunction> {
    let caller_name = caller_name.filter(|s| !s.is_empty())?;
    let candidates = idx.definitions.get(&(file_path.to_string(), caller_name.to_string()))?;
    if candidates.is_empty() {
        return None;
    }
    if candidates.len() == 1 {
        return candidates.iter().next().cloned();
    }
    let eligible = candidates.iter().filter(|c| c.line <= call_line).max_by_key(|c| c.line);
    eligible.or_else(|| candidates.iter().min_by_key(|c| c.line)).cloned()
}

fn record_call_line(idx: &mut AdjacencyIndex, caller: &InternalFunction, callee: &FunctionId, line: i64) {
    let entry = idx.call_lines.entry((caller.clone(), callee.clone())).or_default();
    if !entry.contains(&line) {
        entry.push(line);
        entry.sort_unstable();
    }
}

fn resolved_ancestor_chain(file_path: &str, class_name: &str, idx: &AdjacencyIndex) -> Option<HashSet<String>> {
    let mut seen: HashSet<String> = HashSet::from([class_name.to_string()]);
    let mut stack = vec![class_name.to_string()];
    let mut iterations = 0;
    while let Some(current) = stack.pop() {
        iterations += 1;
        if iterations > 1000 {
            return None;
        }
        let bases = match idx.class_bases.get(&(file_path.to_string(), current.clone())) {
            Some(b) => b.clone(),
            None => {
                if current == class_name {
                    continue;
                }
                return None;
            }
        };
        for b in &bases {
            if b.contains('.') {
                return None;
            }
            if !idx.class_bases.contains_key(&(file_path.to_string(), b.clone())) {
                if SAFE_BUILTIN_BASES.contains(&b.as_str()) {
                    continue;
                }
                return None;
            }
            if !seen.contains(b) {
                seen.insert(b.clone());
                stack.push(b.clone());
            }
        }
    }
    Some(seen)
}

fn method_match_compatible(receiver_class: Option<&str>, receiver_file: &str, target_class: Option<&str>, idx: &AdjacencyIndex) -> bool {
    let Some(receiver_class) = receiver_class else { return true };
    let Some(target_class) = target_class else { return false };
    if receiver_class == target_class {
        return true;
    }
    match resolved_ancestor_chain(receiver_file, receiver_class, idx) {
        None => true,
        Some(chain) => chain.contains(target_class),
    }
}

fn apply_reexport_aliases(idx: &mut AdjacencyIndex, inventory: &Value) -> usize {
    let empty = Vec::new();
    let files = inventory.get("files").and_then(Value::as_array).unwrap_or(&empty);
    let mut added = 0;
    for fr in files {
        if !fr.is_object() {
            continue;
        }
        let path = fr.get("path").and_then(Value::as_str).unwrap_or("");
        if !(path.ends_with("/__init__.py") || path == "__init__.py") {
            continue;
        }
        let Some(cg) = nonempty_cg(fr) else { continue };
        let rel_imports = cg.get("relative_imports").and_then(Value::as_array).cloned().unwrap_or_default();
        let abs_imports = cg.get("imports").and_then(Value::as_object).cloned().unwrap_or_default();
        if rel_imports.is_empty() && abs_imports.is_empty() {
            continue;
        }
        let pkg_path = if path == "__init__.py" { "" } else { path.strip_suffix("/__init__.py").unwrap_or(path) };
        let mut pkg_dotted_candidates: Vec<String> = Vec::new();
        if !pkg_path.is_empty() {
            pkg_dotted_candidates.push(pkg_path.replace('/', "."));
            if let Some(stripped) = pkg_path.strip_prefix("src/") {
                if !stripped.is_empty() {
                    pkg_dotted_candidates.push(stripped.replace('/', "."));
                }
            }
        } else {
            pkg_dotted_candidates.push(String::new());
        }
        for ri in &rel_imports {
            let Some(parts) = ri.as_array() else { continue };
            if parts.len() < 3 {
                continue;
            }
            let level = parts[0].as_i64().unwrap_or(0);
            let module = parts[1].as_str().unwrap_or("");
            let name = parts[2].as_str().unwrap_or("");
            let asname = parts.get(3).and_then(Value::as_str);
            if level <= 0 || name.is_empty() {
                continue;
            }
            for pkg_dotted in &pkg_dotted_candidates {
                let pp: Vec<&str> = if pkg_dotted.is_empty() { Vec::new() } else { pkg_dotted.split('.').collect() };
                let ascend = (level - 1) as usize;
                if ascend > pp.len() {
                    continue;
                }
                let ancestor = if ascend > 0 { pp[..pp.len() - ascend].join(".") } else { pp.join(".") };
                let source_module = if !module.is_empty() {
                    if ancestor.is_empty() { module.to_string() } else { format!("{ancestor}.{module}") }
                } else {
                    ancestor
                };
                if source_module.is_empty() {
                    continue;
                }
                let source_full = format!("{source_module}.{name}");
                let Some(target_internal) = idx.qualified_to_internal.get(&source_full).cloned() else { continue };
                let alias_name = asname.unwrap_or(name);
                let alias_full = if pkg_dotted.is_empty() { alias_name.to_string() } else { format!("{pkg_dotted}.{alias_name}") };
                if let std::collections::hash_map::Entry::Vacant(e) = idx.qualified_to_internal.entry(alias_full) {
                    e.insert(target_internal);
                    added += 1;
                }
            }
        }
        for (local_name, qualified) in &abs_imports {
            let Some(qualified) = qualified.as_str() else { continue };
            if qualified.is_empty() {
                continue;
            }
            let Some(target_internal) = idx.qualified_to_internal.get(qualified).cloned() else { continue };
            for pkg_dotted in &pkg_dotted_candidates {
                let alias_full = if pkg_dotted.is_empty() { local_name.clone() } else { format!("{pkg_dotted}.{local_name}") };
                if alias_full == qualified {
                    continue;
                }
                if let std::collections::hash_map::Entry::Vacant(e) = idx.qualified_to_internal.entry(alias_full) {
                    e.insert(target_internal.clone());
                    added += 1;
                }
            }
        }
    }
    added
}

/// Build the adjacency index (the multi-pass `_get_or_build_index`, sans caches).
pub fn build_adjacency_index(inventory: &Value) -> AdjacencyIndex {
    let mut idx = AdjacencyIndex::default();
    let empty = Vec::new();
    let files = inventory.get("files").and_then(Value::as_array).unwrap_or(&empty);

    // Pass 1: definitions + test_paths.
    for fr in files {
        if !fr.is_object() {
            continue;
        }
        let path = fr.get("path").and_then(Value::as_str).unwrap_or("").to_string();
        if is_test_file(&path) {
            idx.test_paths.insert(path.clone());
        }
        for item in fr.get("items").and_then(Value::as_array).into_iter().flatten() {
            if !item.is_object() {
                continue;
            }
            let keep = match item.get("kind") {
                None | Some(Value::Null) => true,
                Some(v) => v.as_str() == Some("function"),
            };
            if !keep {
                continue;
            }
            let name = item.get("name").and_then(Value::as_str).unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let line = item.get("line_start").and_then(Value::as_i64).unwrap_or(0);
            let fnode = InternalFunction::new(path.clone(), name, line);
            idx.definitions.entry((path.clone(), name.to_string())).or_default().insert(fnode);
        }
    }

    // Pass 1.3: framework_callable (decorators).
    for fr in files {
        let path = fr.get("path").and_then(Value::as_str).unwrap_or("");
        let Some(cg) = nonempty_cg(fr) else { continue };
        for df in cg.get("decorated_functions").and_then(Value::as_array).into_iter().flatten() {
            let Some(df_name) = df.get("name").and_then(Value::as_str) else { continue };
            if df_name.is_empty() {
                continue;
            }
            let df_line = df.get("line").and_then(Value::as_i64).unwrap_or(0);
            let decorators = df.get("decorators").cloned().unwrap_or(Value::Null);
            if !decorators_indicate_framework_dispatch(&decorators) {
                continue;
            }
            if let Some(cands) = idx.definitions.get(&(path.to_string(), df_name.to_string())) {
                if let Some(fnode) = cands.iter().find(|f| f.line == df_line).cloned() {
                    idx.framework_callable.insert(fnode);
                }
            }
        }
    }

    // Pass 1.3b: framework_registered (call-arg registration).
    for fr in files {
        let path = fr.get("path").and_then(Value::as_str).unwrap_or("");
        let Some(cg) = nonempty_cg(fr) else { continue };
        for call in cg.get("calls").and_then(Value::as_array).into_iter().flatten() {
            if !call.is_object() {
                continue;
            }
            let chain = chain_of(call);
            if chain.len() < 2 {
                continue;
            }
            if !FRAMEWORK_REGISTRATION_TAILS.contains(&chain[chain.len() - 1].as_str()) {
                continue;
            }
            for ident in str_array(call, "argument_identifiers") {
                if let Some(cands) = idx.definitions.get(&(path.to_string(), ident.to_string())) {
                    for fnode in cands.clone() {
                        idx.framework_registered.insert(fnode);
                    }
                }
            }
        }
    }

    // Pass 1.4: class metadata (class_bases, override_methods, class_of_method).
    for fr in files {
        let path = fr.get("path").and_then(Value::as_str).unwrap_or("");
        let Some(cg) = nonempty_cg(fr) else { continue };
        for cls in cg.get("classes").and_then(Value::as_array).into_iter().flatten() {
            let Some(cls_name) = cls.get("name").and_then(Value::as_str) else { continue };
            if cls_name.is_empty() || cls.get("nested").and_then(Value::as_bool).unwrap_or(false) {
                continue;
            }
            let bases: Vec<String> = cls
                .get("bases")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string).collect())
                .unwrap_or_default();
            idx.class_bases.insert((path.to_string(), cls_name.to_string()), bases.clone());
            for me in cls.get("methods").and_then(Value::as_array).into_iter().flatten() {
                let Some(me) = me.as_array() else { continue };
                if me.len() < 2 {
                    continue;
                }
                let m_name = me[0].as_str().unwrap_or("");
                let m_line = me[1].as_i64().unwrap_or(0);
                if !bases.is_empty() {
                    idx.override_methods.insert((cls_name.to_string(), m_name.to_string()));
                }
                if let Some(cands) = idx.definitions.get(&(path.to_string(), m_name.to_string())) {
                    if let Some(fnode) = cands.iter().find(|f| f.line == m_line).cloned() {
                        idx.class_of_method.insert(fnode, cls_name.to_string());
                    }
                }
            }
        }
    }

    // Pass 1.5: qualified_to_internal.
    let mut file_packages: HashMap<String, String> = HashMap::new();
    for fr in files {
        let path = fr.get("path").and_then(Value::as_str).unwrap_or("");
        if let Some(cg) = fr.get("call_graph") {
            if let Some(pkg) = cg.get("package_name").and_then(Value::as_str) {
                if !pkg.is_empty() {
                    file_packages.insert(path.to_string(), pkg.to_string());
                }
            }
        }
    }
    let defs_snapshot: Vec<((String, String), HashSet<InternalFunction>)> =
        idx.definitions.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for ((file_path, fn_name), fns) in &defs_snapshot {
        let Some(canonical) = fns.iter().min_by_key(|f| f.line).cloned() else { continue };
        let cls_name = idx.class_of_method.get(&canonical).cloned();
        for candidate in candidate_qualified_names(file_path, fn_name, file_packages.get(file_path).map(String::as_str), cls_name.as_deref()) {
            idx.qualified_to_internal.entry(candidate).or_insert_with(|| canonical.clone());
        }
    }

    // Pass 1.6: re-export aliases to fixed-point (bounded).
    for _ in 0..8 {
        if apply_reexport_aliases(&mut idx, inventory) == 0 {
            break;
        }
    }

    // Pass 2: resolve every call site, record forward/reverse edges.
    for fr in files {
        let path = fr.get("path").and_then(Value::as_str).unwrap_or("").to_string();
        let Some(cg) = nonempty_cg(fr) else { continue };
        let empty_map = Map::new();
        let imports = cg.get("imports").and_then(Value::as_object).unwrap_or(&empty_map).clone();
        let flags: HashSet<&str> = str_array(cg, "indirection").into_iter().collect();
        let getattr_targets: HashSet<&str> = str_array(cg, "getattr_targets").into_iter().collect();
        let non_wildcard_masking: BTreeSet<&str> = flags
            .iter()
            .copied()
            .filter(|f| MASKING_FLAGS.contains(f) && *f != INDIRECTION_WILDCARD_IMPORT)
            .collect();
        let has_wildcard = flags.contains(INDIRECTION_WILDCARD_IMPORT);
        let calls = cg.get("calls").and_then(Value::as_array).cloned().unwrap_or_default();

        for call in &calls {
            let chain = chain_of(call);
            if chain.is_empty() {
                continue;
            }
            let line = call_line(call);
            let caller_name = call.get("caller").and_then(Value::as_str);
            let Some(caller_node) = resolve_caller(&idx, &path, caller_name, line) else { continue };

            if let Some(callee) = resolve_callee_chain(&chain, &imports) {
                let node = match idx.qualified_to_internal.get(&callee.qualified_name) {
                    Some(internal) => FunctionId::Internal(internal.clone()),
                    None => FunctionId::External(callee),
                };
                idx.forward.entry(caller_node.clone()).or_default().insert(node.clone());
                idx.reverse.entry(node.clone()).or_default().insert(caller_node.clone());
                record_call_line(&mut idx, &caller_node, &node, line);
                continue;
            }

            if chain.len() >= 2 {
                let dotted = chain.join(".");
                if let Some(aliased) = idx.qualified_to_internal.get(&dotted).cloned() {
                    let node = FunctionId::Internal(aliased);
                    idx.forward.entry(caller_node.clone()).or_default().insert(node.clone());
                    idx.reverse.entry(node.clone()).or_default().insert(caller_node.clone());
                    record_call_line(&mut idx, &caller_node, &node, line);
                    continue;
                }
            }

            let tail = chain[chain.len() - 1].clone();
            if chain.len() == 1 {
                if let Some(local_defs) = idx.definitions.get(&(path.clone(), tail.clone())).cloned() {
                    if !local_defs.is_empty() {
                        for d in local_defs {
                            let node = FunctionId::Internal(d.clone());
                            idx.forward.entry(caller_node.clone()).or_default().insert(node.clone());
                            idx.reverse.entry(node.clone()).or_default().insert(caller_node.clone());
                            record_call_line(&mut idx, &caller_node, &node, line);
                        }
                        continue;
                    }
                }
                if has_wildcard {
                    idx.uncertain_callees.entry(caller_node.clone()).or_default().insert(format!("*.{tail}"));
                }
                continue;
            }

            let receiver_class = call.get("receiver_class").and_then(Value::as_str).map(str::to_string);
            idx.method_match.entry(tail.clone()).or_default().insert((caller_node.clone(), receiver_class));
            idx.has_method_dispatch.insert(caller_node.clone(), true);
            idx.uncertain_callees.entry(caller_node.clone()).or_default().insert(chain.join("."));
        }

        // File-level masking → every internal fn in this file becomes an
        // uncertain caller for any tail the file mentions.
        if !non_wildcard_masking.is_empty() || has_wildcard {
            let file_internal_fns: Vec<InternalFunction> = idx
                .definitions
                .iter()
                .filter(|((p, _), _)| *p == path)
                .flat_map(|(_, fns)| fns.iter().cloned())
                .collect();
            let mut mentioned_tails: HashSet<String> = getattr_targets.iter().map(|s| s.to_string()).collect();
            for call in &calls {
                let chain = chain_of(call);
                if let Some(t) = chain.last() {
                    mentioned_tails.insert(t.clone());
                }
            }
            for qualified in imports.values() {
                if let Some(s) = qualified.as_str() {
                    if !s.is_empty() {
                        mentioned_tails.insert(s.rsplit('.').next().unwrap_or("").to_string());
                    }
                }
            }
            let flag_label = non_wildcard_masking
                .iter()
                .next()
                .map(|s| s.to_string())
                .unwrap_or_else(|| INDIRECTION_WILDCARD_IMPORT.to_string());
            for tail in &mentioned_tails {
                for fnode in &file_internal_fns {
                    idx.uncertain_callers_by_tail
                        .entry(tail.clone())
                        .or_default()
                        .insert((fnode.clone(), flag_label.clone()));
                }
            }
        }
    }

    idx
}

fn sorted_internal(s: impl IntoIterator<Item = InternalFunction>) -> Vec<InternalFunction> {
    let mut v: Vec<InternalFunction> = s.into_iter().collect();
    v.sort_by(|a, b| (a.file_path.as_str(), a.name.as_str(), a.line).cmp(&(b.file_path.as_str(), b.name.as_str(), b.line)));
    v
}

fn sorted_callees(s: impl IntoIterator<Item = FunctionId>) -> Vec<FunctionId> {
    let mut internals: Vec<InternalFunction> = Vec::new();
    let mut externals: Vec<ExternalFunction> = Vec::new();
    for c in s {
        match c {
            FunctionId::Internal(f) => internals.push(f),
            FunctionId::External(f) => externals.push(f),
        }
    }
    internals.sort_by(|a, b| (a.file_path.as_str(), a.name.as_str(), a.line).cmp(&(b.file_path.as_str(), b.name.as_str(), b.line)));
    externals.sort_by(|a, b| a.qualified_name.cmp(&b.qualified_name));
    internals.into_iter().map(FunctionId::Internal).chain(externals.into_iter().map(FunctionId::External)).collect()
}

/// 1-hop callers of `target` (`callers_of`).
pub fn callers_of(inventory: &Value, target: &FunctionId, exclude_test_files: bool) -> CallersResult {
    let idx = build_adjacency_index(inventory);
    callers_of_indexed(&idx, target, exclude_test_files)
}

fn callers_of_indexed(idx: &AdjacencyIndex, target: &FunctionId, exclude_test_files: bool) -> CallersResult {
    // ExternalFunction aliasing -> InternalFunction.
    let target = match target {
        FunctionId::External(e) => match idx.qualified_to_internal.get(&e.qualified_name) {
            Some(internal) => FunctionId::Internal(internal.clone()),
            None => target.clone(),
        },
        _ => target.clone(),
    };

    let mut definitive: HashSet<InternalFunction> = idx.reverse.get(&target).cloned().unwrap_or_default();

    let target_tail = match &target {
        FunctionId::Internal(f) => f.name.clone(),
        FunctionId::External(e) => e.qualified_name.rsplit('.').next().unwrap_or("").to_string(),
    };
    let uncertain_pairs = idx.uncertain_callers_by_tail.get(&target_tail).cloned().unwrap_or_default();
    let mut uncertain: HashSet<InternalFunction> =
        uncertain_pairs.into_iter().map(|(fn_, _)| fn_).filter(|fn_| !definitive.contains(fn_)).collect();

    let mut method_match_set: HashSet<InternalFunction> = HashSet::new();
    if let FunctionId::Internal(t) = &target {
        if let Some(cands) = idx.method_match.get(&t.name) {
            let target_class = idx.class_of_method.get(t).map(String::as_str);
            for (caller, receiver_class) in cands {
                if method_match_compatible(receiver_class.as_deref(), &caller.file_path, target_class, idx) {
                    method_match_set.insert(caller.clone());
                }
            }
            method_match_set.retain(|f| !definitive.contains(f) && !uncertain.contains(f));
        }
    }

    if exclude_test_files {
        definitive.retain(|f| !idx.test_paths.contains(&f.file_path));
        uncertain.retain(|f| !idx.test_paths.contains(&f.file_path));
        method_match_set.retain(|f| !idx.test_paths.contains(&f.file_path));
    }

    CallersResult {
        definitive: sorted_internal(definitive),
        uncertain: sorted_internal(uncertain),
        method_match_overinclusive: sorted_internal(method_match_set),
    }
}

/// 1-hop callees of internal `source` (`callees_of`).
pub fn callees_of(inventory: &Value, source: &InternalFunction, exclude_test_files: bool) -> CalleesResult {
    let idx = build_adjacency_index(inventory);
    let mut definitive: HashSet<FunctionId> = idx.forward.get(source).cloned().unwrap_or_default();
    let uncertain: HashSet<String> = idx.uncertain_callees.get(source).cloned().unwrap_or_default();
    let has_method_dispatch = idx.has_method_dispatch.get(source).copied().unwrap_or(false);

    if exclude_test_files {
        definitive.retain(|c| !matches!(c, FunctionId::Internal(f) if idx.test_paths.contains(&f.file_path)));
    }
    let mut uncertain_v: Vec<String> = uncertain.into_iter().collect();
    uncertain_v.sort();
    CalleesResult { definitive: sorted_callees(definitive), uncertain: uncertain_v, has_method_dispatch }
}

/// Source lines where `caller` calls `callee` (`call_lines_of`).
pub fn call_lines_of(inventory: &Value, caller: &InternalFunction, callee: &FunctionId) -> Vec<i64> {
    let idx = build_adjacency_index(inventory);
    let callee = match callee {
        FunctionId::External(e) => match idx.qualified_to_internal.get(&e.qualified_name) {
            Some(internal) => FunctionId::Internal(internal.clone()),
            None => callee.clone(),
        },
        _ => callee.clone(),
    };
    idx.call_lines.get(&(caller.clone(), callee)).cloned().unwrap_or_default()
}

/// True iff `target` carries a framework-dispatch registration decorator.
pub fn is_framework_callable(inventory: &Value, target: &InternalFunction) -> bool {
    build_adjacency_index(inventory).framework_callable.contains(target)
}

/// True iff `target` is registered as a handler via a framework call argument.
pub fn is_registered_via_call(inventory: &Value, target: &InternalFunction) -> bool {
    build_adjacency_index(inventory).framework_registered.contains(target)
}

/// CHA: is `(class_name, method_name)` a polymorphic override dispatched via an
/// unresolved member call (`is_virtual_dispatch_candidate`)?
pub fn is_virtual_dispatch_candidate(inventory: &Value, class_name: Option<&str>, method_name: &str) -> bool {
    let Some(class_name) = class_name else { return false };
    let idx = build_adjacency_index(inventory);
    idx.override_methods.contains(&(class_name.to_string(), method_name.to_string())) && idx.method_match.contains_key(method_name)
}

// ---------------------------------------------------------------------------
// Closures + entry-reachability — BFS over the adjacency index.
// Port of ClosureResult + reverse_closure/forward_closure/shortest_path +
// _entry_functions/_entry_reachable_set/entry_reachability.
// ---------------------------------------------------------------------------

use std::collections::VecDeque;

const ENTRY_CLOSURE_MAX_DEPTH: i64 = 100_000;
/// Languages whose entry model is a closed, sound signal (entry_model == "sound").
const CLOSEABLE_ENTRY_LANGS: &[&str] = &["c", "cpp", "go", "rust"];

/// Result of a transitive closure walk (`ClosureResult`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClosureResult {
    pub nodes: Vec<FunctionId>,
    pub paths: HashMap<FunctionId, Vec<FunctionId>>,
    pub truncated: bool,
}

/// Stable mixed-node order: Internal first by (path, name, line), External after
/// by qualified_name (`_closure_sort_key`).
fn closure_sort_key(fid: &FunctionId) -> (u8, &str, &str, i64, &str) {
    match fid {
        FunctionId::Internal(f) => (0, f.file_path.as_str(), f.name.as_str(), f.line, ""),
        FunctionId::External(e) => (1, "", "", 0, e.qualified_name.as_str()),
    }
}

fn sort_closure_nodes(nodes: &mut [FunctionId]) {
    nodes.sort_by(|a, b| closure_sort_key(a).cmp(&closure_sort_key(b)));
}

fn alias_target(idx: &AdjacencyIndex, target: &FunctionId) -> FunctionId {
    match target {
        FunctionId::External(e) => match idx.qualified_to_internal.get(&e.qualified_name) {
            Some(internal) => FunctionId::Internal(internal.clone()),
            None => target.clone(),
        },
        _ => target.clone(),
    }
}

fn reverse_closure_indexed(idx: &AdjacencyIndex, target: &FunctionId, max_depth: i64, exclude_test_files: bool) -> ClosureResult {
    let target = alias_target(idx, target);
    let mut paths: HashMap<FunctionId, Vec<FunctionId>> = HashMap::new();
    paths.insert(target.clone(), vec![target.clone()]);
    let mut queue: VecDeque<(FunctionId, i64)> = VecDeque::from([(target.clone(), 0)]);
    let mut truncated = false;
    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            truncated = true;
            continue;
        }
        let Some(callers) = idx.reverse.get(&node).cloned() else { continue };
        for caller in callers {
            if exclude_test_files && idx.test_paths.contains(&caller.file_path) {
                continue;
            }
            let cnode = FunctionId::Internal(caller);
            if paths.contains_key(&cnode) {
                continue;
            }
            let mut newpath = vec![cnode.clone()];
            newpath.extend(paths[&node].clone());
            paths.insert(cnode.clone(), newpath);
            queue.push_back((cnode, depth + 1));
        }
    }
    finish_closure(paths, |n| *n == target, truncated)
}

fn forward_closure_indexed(idx: &AdjacencyIndex, entries: impl Iterator<Item = InternalFunction>, max_depth: i64, exclude_test_files: bool) -> ClosureResult {
    let entry_set: HashSet<FunctionId> = entries.map(FunctionId::Internal).collect();
    let mut paths: HashMap<FunctionId, Vec<FunctionId>> = HashMap::new();
    let mut queue: VecDeque<(FunctionId, i64)> = VecDeque::new();
    for entry in &entry_set {
        paths.entry(entry.clone()).or_insert_with(|| {
            queue.push_back((entry.clone(), 0));
            vec![entry.clone()]
        });
    }
    let mut truncated = false;
    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            truncated = true;
            continue;
        }
        // External nodes are terminal.
        let FunctionId::Internal(inner) = &node else { continue };
        let Some(callees) = idx.forward.get(inner).cloned() else { continue };
        for callee in callees {
            if paths.contains_key(&callee) {
                continue;
            }
            if exclude_test_files {
                if let FunctionId::Internal(f) = &callee {
                    if idx.test_paths.contains(&f.file_path) {
                        continue;
                    }
                }
            }
            let mut newpath = paths[&node].clone();
            newpath.push(callee.clone());
            paths.insert(callee.clone(), newpath);
            queue.push_back((callee, depth + 1));
        }
    }
    finish_closure(paths, |n| entry_set.contains(n), truncated)
}

fn finish_closure(paths: HashMap<FunctionId, Vec<FunctionId>>, is_seed: impl Fn(&FunctionId) -> bool, truncated: bool) -> ClosureResult {
    let mut nodes: Vec<FunctionId> = Vec::new();
    let mut out_paths: HashMap<FunctionId, Vec<FunctionId>> = HashMap::new();
    for (n, p) in paths {
        if is_seed(&n) {
            continue;
        }
        nodes.push(n.clone());
        out_paths.insert(n, p);
    }
    sort_closure_nodes(&mut nodes);
    ClosureResult { nodes, paths: out_paths, truncated }
}

/// Project functions that can transitively reach `target` (`reverse_closure`).
pub fn reverse_closure(inventory: &Value, target: &FunctionId, max_depth: i64, exclude_test_files: bool) -> ClosureResult {
    let idx = build_adjacency_index(inventory);
    reverse_closure_indexed(&idx, target, max_depth, exclude_test_files)
}

/// Functions transitively callable from any of `entries` (`forward_closure`).
pub fn forward_closure(inventory: &Value, entries: impl Iterator<Item = InternalFunction>, max_depth: i64, exclude_test_files: bool) -> ClosureResult {
    let idx = build_adjacency_index(inventory);
    forward_closure_indexed(&idx, entries, max_depth, exclude_test_files)
}

/// Shortest call chain `source` -> `target`, or `None` (`shortest_path`).
pub fn shortest_path(inventory: &Value, source: &InternalFunction, target: &FunctionId, max_depth: i64, exclude_test_files: bool) -> Option<Vec<FunctionId>> {
    let idx = build_adjacency_index(inventory);
    let target = alias_target(&idx, target);
    let source_fid = FunctionId::Internal(source.clone());
    if source_fid == target {
        return Some(vec![source_fid]);
    }
    let mut visited: HashMap<FunctionId, Vec<FunctionId>> = HashMap::from([(source_fid.clone(), vec![source_fid.clone()])]);
    let mut queue: VecDeque<(FunctionId, i64)> = VecDeque::from([(source_fid, 0)]);
    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        let FunctionId::Internal(inner) = &node else { continue };
        let Some(callees) = idx.forward.get(inner).cloned() else { continue };
        for callee in callees {
            if visited.contains_key(&callee) {
                continue;
            }
            let mut chain = visited[&node].clone();
            chain.push(callee.clone());
            if callee == target {
                if exclude_test_files {
                    let crosses_test = chain[1..chain.len() - 1]
                        .iter()
                        .any(|s| matches!(s, FunctionId::Internal(f) if idx.test_paths.contains(&f.file_path)));
                    if crosses_test {
                        continue;
                    }
                }
                return Some(chain);
            }
            if exclude_test_files {
                if let FunctionId::Internal(f) = &callee {
                    if idx.test_paths.contains(&f.file_path) {
                        continue;
                    }
                }
            }
            visited.insert(callee.clone(), chain);
            queue.push_back((callee, depth + 1));
        }
    }
    None
}

/// The InternalFunction entry-point set (visibility/linkage + framework dispatch).
fn entry_functions(inventory: &Value, idx: &AdjacencyIndex) -> HashSet<InternalFunction> {
    let mut entries: HashSet<InternalFunction> = HashSet::new();
    let empty = Vec::new();
    let files = inventory.get("files").and_then(Value::as_array).unwrap_or(&empty);
    for fr in files {
        if !fr.is_object() {
            continue;
        }
        let lang = fr.get("language").and_then(Value::as_str).unwrap_or("");
        let path = fr.get("path").and_then(Value::as_str).unwrap_or("");
        for item in fr.get("items").and_then(Value::as_array).into_iter().flatten() {
            if !item.is_object() {
                continue;
            }
            // _entry_functions defaults absent kind to "function"; explicit null
            // is treated as non-function and skipped (differs from index pass 1).
            let is_fn = match item.get("kind") {
                None => true,
                Some(Value::String(s)) => s == "function",
                _ => false,
            };
            if !is_fn {
                continue;
            }
            if item_is_entry(item, lang) {
                let name = item.get("name").and_then(Value::as_str).unwrap_or("");
                let line = item.get("line_start").and_then(Value::as_i64).unwrap_or(0);
                entries.insert(InternalFunction::new(path, name, line));
            }
        }
    }
    entries.extend(idx.framework_callable.iter().cloned());
    entries.extend(idx.framework_registered.iter().cloned());
    entries
}

fn entry_reachable_set(inventory: &Value) -> (HashSet<InternalFunction>, bool) {
    let idx = build_adjacency_index(inventory);
    let entries = entry_functions(inventory, &idx);
    let fc = forward_closure_indexed(&idx, entries.iter().cloned(), ENTRY_CLOSURE_MAX_DEPTH, true);
    let mut reachable = entries;
    for n in fc.nodes {
        if let FunctionId::Internal(f) = n {
            reachable.insert(f);
        }
    }
    (reachable, fc.truncated)
}

/// `"reachable"` | `"no_path_from_entry"` | `"uncertain"` (`entry_reachability`).
pub fn entry_reachability(inventory: &Value, target: &InternalFunction, max_depth: i64) -> &'static str {
    let (reachable, truncated) = entry_reachable_set(inventory);
    if reachable.contains(target) {
        return "reachable";
    }
    if truncated {
        return "uncertain";
    }
    match file_language(inventory, &target.file_path) {
        Some(l) if CLOSEABLE_ENTRY_LANGS.contains(&l.as_str()) => {}
        _ => return "uncertain",
    }
    if file_has_masking(inventory, &target.file_path) {
        return "uncertain";
    }
    let rc = reverse_closure(inventory, &FunctionId::Internal(target.clone()), max_depth, true);
    for fid in rc.nodes {
        if let FunctionId::Internal(f) = fid {
            if file_has_masking(inventory, &f.file_path) {
                return "uncertain";
            }
        }
    }
    "no_path_from_entry"
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inv() -> Value {
        json!({
            "files": [
                {
                    "path": "src/a.py",
                    "module_aborts_on_load": {"line": 2, "summary": "raise ImportError"},
                    "items": [
                        {"name": "dead_fn", "line_start": 4, "lexical_dead": true},
                        {"name": "live_fn", "line_start": 8},
                    ],
                },
                {
                    "path": "pkg\\b.go",
                    "build_excluded": {"line": 1, "summary": "//go:build ignore"},
                    "items": [],
                },
            ]
        })
    }

    #[test]
    fn path_helpers() {
        assert!(is_test_file("tests/x.py"));
        assert!(is_test_file("src/test_foo.py"));
        assert!(is_test_file("src/foo_test.py"));
        assert!(is_test_file("conftest.py"));
        assert!(!is_test_file("src/handler.py"));
        assert!(!is_test_file("testdata/x.py"));

        assert_eq!(file_path_to_module("c/heartbeat.c").as_deref(), Some("c.heartbeat"));
        assert_eq!(file_path_to_module("packages/foo/bar.py").as_deref(), Some("packages.foo.bar"));
        assert_eq!(file_path_to_module("Makefile"), None);
        assert_eq!(file_path_to_module(".bashrc"), None);

        assert_eq!(
            path_derived_module("src/api/handler.py", "Cls", "fn"),
            vec!["src.api.handler.Cls.fn", "api.handler.Cls.fn"]
        );
        assert_eq!(path_derived_module("foo/__init__.py", "C", "m"), vec!["foo.C.m"]);
        assert_eq!(path_derived_module("main.c", "C", "m"), Vec::<String>::new());
    }

    #[test]
    fn internal_function_display() {
        assert_eq!(InternalFunction::new("a.py", "f", 4).display(), "a.py:f@4");
    }

    #[test]
    fn function_called_import_and_bare() {
        let inv = json!({"files": [
            {"path": "src/app.py", "call_graph": {
                "imports": {"ezp": "requests.utils.extract_zipped_paths"},
                "calls": [{"chain": ["ezp"], "line": 12}]
            }},
            {"path": "tests/test_app.py", "call_graph": {
                "imports": {"ezp": "requests.utils.extract_zipped_paths"},
                "calls": [{"chain": ["ezp"], "line": 3}]
            }}
        ]});
        let r = function_called(&inv, "requests.utils.extract_zipped_paths", true).unwrap();
        assert_eq!(r.verdict, Verdict::Called);
        // Test file excluded -> only the src evidence.
        assert_eq!(r.evidence, vec![("src/app.py".to_string(), 12)]);
    }

    #[test]
    fn function_called_uncertain_and_not_called() {
        let inv = json!({"files": [
            {"path": "src/wild.py", "call_graph": {"imports": {"os": "requests.helpers"}, "indirection": ["wildcard_import"]}}
        ]});
        let r = function_called(&inv, "requests.helpers.thing", true).unwrap();
        assert_eq!(r.verdict, Verdict::Uncertain);
        assert_eq!(r.uncertain_reasons, vec![("src/wild.py".to_string(), "wildcard_import".to_string())]);

        let r2 = function_called(&inv, "totally.unrelated.fn", true).unwrap();
        assert_eq!(r2.verdict, Verdict::NotCalled);
    }

    #[test]
    fn closures_and_entry_reachability() {
        let inv = json!({"files": [
            {"path": "main.go", "language": "go",
             "items": [{"name": "main", "line_start": 1, "kind": "function"}, {"name": "Helper", "line_start": 10, "kind": "function"}, {"name": "deep", "line_start": 20, "kind": "function"}, {"name": "orphan", "line_start": 30, "kind": "function"}],
             "call_graph": {"package_name": "app", "imports": {},
               "calls": [
                 {"chain": ["Helper"], "line": 2, "caller": "main"},
                 {"chain": ["deep"], "line": 11, "caller": "Helper"},
                 {"chain": ["deep"], "line": 31, "caller": "orphan"}
               ]}}
        ]});
        let main_fn = InternalFunction::new("main.go", "main", 1);
        let helper = InternalFunction::new("main.go", "Helper", 10);
        let deep = InternalFunction::new("main.go", "deep", 20);
        let orphan = InternalFunction::new("main.go", "orphan", 30);

        // forward closure from main reaches Helper + deep (not orphan).
        let fc = forward_closure(&inv, std::iter::once(main_fn.clone()), 50, true);
        assert_eq!(fc.nodes, vec![FunctionId::Internal(helper.clone()), FunctionId::Internal(deep.clone())]);

        // reverse closure of deep: Helper, main, orphan all reach it.
        let rc = reverse_closure(&inv, &FunctionId::Internal(deep.clone()), 50, true);
        let rc_set: std::collections::HashSet<_> = rc.nodes.into_iter().collect();
        assert!(rc_set.contains(&FunctionId::Internal(helper.clone())));
        assert!(rc_set.contains(&FunctionId::Internal(main_fn.clone())));
        assert!(rc_set.contains(&FunctionId::Internal(orphan.clone())));

        // shortest path main -> deep is [main, Helper, deep]; main -> orphan is None.
        assert_eq!(
            shortest_path(&inv, &main_fn, &FunctionId::Internal(deep.clone()), 50, false),
            Some(vec![FunctionId::Internal(main_fn.clone()), FunctionId::Internal(helper), FunctionId::Internal(deep.clone())])
        );
        assert_eq!(shortest_path(&inv, &main_fn, &FunctionId::Internal(orphan.clone()), 50, false), None);

        // entry_reachability: main reachable; deep reachable via main; orphan dead (Go is closeable).
        assert_eq!(entry_reachability(&inv, &main_fn, 50), "reachable");
        assert_eq!(entry_reachability(&inv, &deep, 50), "reachable");
        assert_eq!(entry_reachability(&inv, &orphan, 50), "no_path_from_entry");
    }

    #[test]
    fn adjacency_callers_callees_and_framework() {
        let inv = json!({"files": [
            {"path": "app/main.py", "language": "python",
             "items": [{"name": "run", "line_start": 5, "kind": "function"}, {"name": "helper", "line_start": 1, "kind": "function"}],
             "call_graph": {"imports": {"util": "app.util"},
               "calls": [
                 {"chain": ["helper"], "line": 6, "caller": "run"},
                 {"chain": ["util", "do"], "line": 7, "caller": "run"}
               ],
               "decorated_functions": [{"name": "run", "line": 5, "decorators": [["app", "route"]]}]
             }},
            {"path": "app/util.py", "language": "python",
             "items": [{"name": "do", "line_start": 2, "kind": "function"}],
             "call_graph": {"imports": {}, "calls": []}}
        ]});
        let run = InternalFunction::new("app/main.py", "run", 5);
        let helper = InternalFunction::new("app/main.py", "helper", 1);
        let do_fn = InternalFunction::new("app/util.py", "do", 2);

        // callees of run -> helper (local) + do (import-resolved, canonicalised to internal).
        let callees = callees_of(&inv, &run, true);
        assert!(callees.definitive.contains(&FunctionId::Internal(helper.clone())));
        assert!(callees.definitive.contains(&FunctionId::Internal(do_fn.clone())));

        // callers of do -> run (cross-file import edge canonicalised).
        let callers = callers_of(&inv, &FunctionId::Internal(do_fn.clone()), true);
        assert_eq!(callers.definitive, vec![run.clone()]);

        // call lines run -> do.
        assert_eq!(call_lines_of(&inv, &run, &FunctionId::Internal(do_fn)), vec![7]);

        // run is framework-callable (@app.route); helper is not.
        assert!(is_framework_callable(&inv, &run));
        assert!(!is_framework_callable(&inv, &helper));
    }

    #[test]
    fn file_language_and_masking() {
        let inv = json!({"files": [
            {"path": "src/a.py", "language": "python", "call_graph": {"indirection": ["getattr"]}},
            {"path": "c/m.c", "language": "c", "call_graph": {"macro_call_targets": ["FOO"]}},
            {"path": "src/clean.py", "language": "python", "call_graph": {"indirection": []}},
        ]});
        assert_eq!(file_language(&inv, "src/a.py").as_deref(), Some("python"));
        assert_eq!(file_language(&inv, "missing.py"), None);
        assert!(file_has_masking(&inv, "src/a.py")); // getattr flag
        assert!(file_has_masking(&inv, "c/m.c")); // macro targets
        assert!(!file_has_masking(&inv, "src/clean.py"));
        assert!(!file_has_masking(&inv, "missing.py"));
    }

    #[test]
    fn function_called_rejects_non_dotted() {
        let inv = json!({"files": []});
        assert!(function_called(&inv, "open", true).is_err());
    }

    #[test]
    fn verdict_strings() {
        assert_eq!(Verdict::Called.as_str(), "called");
        assert_eq!(Verdict::NotCalled.as_str(), "not_called");
        assert_eq!(Verdict::Uncertain.as_str(), "uncertain");
    }

    #[test]
    fn module_aborts_lookup() {
        let i = inv();
        assert_eq!(module_aborts_on_load(&i, "src/a.py").unwrap()["summary"], json!("raise ImportError"));
        assert_eq!(module_aborts_on_load(&i, "pkg/b.go"), None);
        assert_eq!(module_aborts_on_load(&i, "missing.py"), None);
        assert_eq!(module_aborts_on_load(&i, ""), None);
    }

    #[test]
    fn build_excluded_lookup_normalises_backslash() {
        let i = inv();
        // Stored path uses a backslash; query with forward slash matches.
        assert_eq!(build_excluded(&i, "pkg/b.go").unwrap()["summary"], json!("//go:build ignore"));
        assert_eq!(build_excluded(&i, "src/a.py"), None);
    }

    #[test]
    fn item_is_entry_visibility_and_framework() {
        // C: extern is an entry, static is not.
        assert!(item_is_entry(&json!({"name": "f", "metadata": {"visibility": "extern"}}), "c"));
        assert!(!item_is_entry(&json!({"name": "f", "metadata": {"visibility": "static"}}), "c"));
        // Go: exported / capitalised / init are entries.
        assert!(item_is_entry(&json!({"name": "Foo"}), "go"));
        assert!(item_is_entry(&json!({"name": "init"}), "go"));
        assert!(!item_is_entry(&json!({"name": "lower"}), "go"));
        // main is an entry in any language.
        assert!(item_is_entry(&json!({"name": "main"}), "python"));
        // Python public is NOT a visibility entry.
        assert!(!item_is_entry(&json!({"name": "f", "metadata": {"visibility": "public"}}), "python"));
    }

    #[test]
    fn item_is_entry_framework_annotations() {
        // Java dispatch annotation (fully-qualified, with args -> tail-matched).
        assert!(item_is_entry(&json!({"name": "h", "metadata": {"attributes": ["org.spring.GetMapping(\"/x\")"]}}), "java"));
        // Java stereotype only promotes PUBLIC methods.
        assert!(item_is_entry(&json!({"name": "m", "metadata": {"visibility": "public", "class_attributes": ["Service"]}}), "java"));
        assert!(!item_is_entry(&json!({"name": "m", "metadata": {"visibility": "private", "class_attributes": ["Service"]}}), "java"));
        // Ruby `*Controller` convention.
        assert!(item_is_entry(&json!({"name": "show", "metadata": {"class_attributes": ["UsersController"]}}), "ruby"));
    }

    #[test]
    fn lexical_dead_exact_and_name_only() {
        let i = inv();
        assert!(is_lexically_dead(&i, "src/a.py", "dead_fn", 4));
        assert!(is_lexically_dead(&i, "src/a.py", "dead_fn", 0)); // name-only
        assert!(!is_lexically_dead(&i, "src/a.py", "dead_fn", 99)); // wrong line
        assert!(!is_lexically_dead(&i, "src/a.py", "live_fn", 8));
        assert!(!is_lexically_dead(&i, "src/a.py", "ghost", 0));
        assert!(!is_lexically_dead(&i, "nope.py", "dead_fn", 4));
    }
}
