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

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

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
