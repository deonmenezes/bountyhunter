//! Faithful Rust port of `core/config/__init__.py` (`MantishackConfig`).
//!
//! Behaviour-preserving: same inputs → same outputs. `MantishackConfig` is a
//! class-level namespace in Python; here it is a module of constants and free
//! functions ([`get_safe_env`], [`get_llm_env`], [`get_git_env`],
//! [`get_out_dir`], …) plus tuning-backed accessors.
//!
//! ## Cycle break
//! Python `MantishackConfig.get_safe_env()` lazily imports `strip_env_vars`
//! from `core.security.env_sanitisation` (runtime, function-local). This crate
//! mirrors that with a normal compile-time dependency on
//! `mantishack_core_security` (the lower crate). The reverse edge — cc_trust's
//! lazy import of `MantishackConfig.DANGEROUS_ENV_VARS` — is satisfied via
//! [`install_security_injection`], which pushes [`DANGEROUS_ENV_VARS`] into the
//! security crate's injection point so cc_trust matches the config-present path.

use std::path::PathBuf;

use mantishack_core_security::env_sanitisation::{strip_env_vars, EnvMap};

// ───────────────────────── version / limits ────────────────────────────────

pub const VERSION: &str = "3.0.0";

// Timeout configuration (seconds).
pub const DEFAULT_TIMEOUT: i64 = 1800;
pub const SEMGREP_TIMEOUT: i64 = 900;
pub const SEMGREP_PACK_TIMEOUT: i64 = 300;
pub const SEMGREP_RULE_TIMEOUT: i64 = 120;
pub const CODEQL_TIMEOUT: i64 = 1800;
pub const CODEQL_ANALYZE_TIMEOUT: i64 = 2400;
pub const GIT_CLONE_TIMEOUT: i64 = 600;
pub const LLM_TIMEOUT: i64 = 120;
pub const SUBPROCESS_POLL_INTERVAL: i64 = 1;

// Resource limits.
pub const RESOURCE_READ_LIMIT: i64 = 5 * 1024 * 1024;
pub const MAX_TAIL_BYTES: i64 = 2000;
pub const HASH_CHUNK_SIZE: i64 = 1024 * 1024;
pub const MAX_FILE_SIZE_FOR_HASH: i64 = 100 * 1024 * 1024;

// CodeQL DB cache.
pub const CODEQL_DB_MISSING_METADATA_GRACE: i64 = 60;
pub const CODEQL_MAX_PATHS: i64 = 4;
pub const CODEQL_DB_CACHE_DAYS: i64 = 7;
pub const CODEQL_DB_AUTO_CLEANUP: bool = true;
pub const IRIS_TIER1_ENABLED: bool = true;

// Policy defaults.
pub const DEFAULT_POLICY_VERSION: &str = "v1";
pub const DEFAULT_POLICY_GROUPS: &str = "all";

// MCP / logging.
pub const MCP_VERSION: &str = "0.6.0";
pub const LOG_FORMAT_CONSOLE: &str = "[%(levelname)s] %(message)s";
pub const LOG_FORMAT_FILE: &str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s";

// Environment variable names.
pub const ENV_OUT_DIR: &str = "MANTISHACK_OUT_DIR";
pub const ENV_JOB_ID: &str = "MANTISHACK_JOB_ID";
pub const ENV_LLM_CMD: &str = "MANTISHACK_LLM_CMD";

/// `OLLAMA_HOST` is re-read from the environment on every access (Python uses a
/// descriptor for this exact reason — late env changes must be observed).
pub fn ollama_host() -> String {
    std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://localhost:11434".to_string())
}

// ───────────────────────── env allow/block lists ───────────────────────────

/// `SAFE_ENV_ALLOWLIST` — names kept by [`get_safe_env`]'s primary filter.
pub const SAFE_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "USER", "LOGNAME", "HOSTNAME",
    "HOME", "SHELL", "PWD", "OLDPWD",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR", "XDG_SESSION_ID", "XDG_SESSION_TYPE",
    "LANG", "LANGUAGE", "LC_ALL",
    "TERM", "COLORTERM",
    "TZ",
    "DISPLAY",
    "DEBIAN_FRONTEND",
    "PYTHONUNBUFFERED",
    "_MANTISHACK_TRUSTED", "CLAUDECODE",
    "MANTISHACK_OUT_DIR", "MANTISHACK_DIR",
];

/// `SAFE_ENV_PREFIXES` — name prefixes whose whole family is allowlisted.
pub const SAFE_ENV_PREFIXES: &[&str] = &["LC_"];

/// `PROXY_ENV_VARS` — proxy overrides stripped unless `preserve_proxy`.
pub const PROXY_ENV_VARS: &[&str] = &[
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "no_proxy",
];

/// `DANGEROUS_ENV_VARS` — blocklist overlay (verbatim, including the two
/// duplicated `MALLOC_*` entries the Python list carries).
pub const DANGEROUS_ENV_VARS: &[&str] = &[
    "TERMINAL", "BROWSER", "PAGER", "VISUAL", "EDITOR", "IFS", "CDPATH",
    "BASH_ENV", "ENV", "PROMPT_COMMAND", "LD_PRELOAD", "LD_LIBRARY_PATH",
    "LD_AUDIT", "LD_DEBUG", "LD_PROFILE", "LD_SHOW_AUXV", "GCONV_PATH",
    "LOCPATH", "NLSPATH", "HOSTALIASES", "RES_OPTIONS", "LOCALDOMAIN",
    "MALLOC_CHECK_", "MALLOC_PERTURB_", "MALLOC_ARENA_MAX",
    "MALLOC_MMAP_THRESHOLD_", "MALLOC_TRIM_THRESHOLD_", "TMPDIR",
    "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "PYTHONINSPECT", "PERL5OPT",
    "PERLLIB", "PERL5LIB", "RUBYOPT", "RUBYLIB", "NODE_OPTIONS", "NODE_PATH",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "OPENSSL_CONF", "PYTHONUSERBASE",
    "VIRTUAL_ENV", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG",
    "GIT_SSH_COMMAND", "GIT_SSH", "SSH_ASKPASS", "PYTHONBREAKPOINT",
    "KUBECONFIG", "GNUTLS_SYSTEM_PRIORITY_FILE", "NODE_EXTRA_CA_CERTS",
    "SSLKEYLOGFILE", "KRB5_CONFIG", "KRB5CCNAME", "CLASSPATH", "MAVEN_OPTS",
    "GRADLE_OPTS", "CARGO_HOME", "GEM_HOME", "GEM_PATH", "BUNDLE_GEMFILE",
    "PHPRC", "PHP_INI_SCAN_DIR", "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR",
    "EMACSLOADPATH", "DOCKER_CONFIG", "DOCKER_HOST", "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "MALLOC_CONF",
    "JE_MALLOC_CONF", "MALLOC_CHECK_", "MALLOC_PERTURB_",
];

/// `LLM_API_KEY_VARS` — credentials layered on by [`get_llm_env`].
pub const LLM_API_KEY_VARS: &[&str] = &[
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "MISTRAL_API_KEY",
    "GOOGLE_API_KEY", "GROQ_API_KEY", "TOGETHER_API_KEY", "OPENROUTER_API_KEY",
    "FIREWORKS_API_KEY", "DEEPINFRA_API_KEY", "PERPLEXITY_API_KEY",
    "REPLICATE_API_TOKEN", "COHERE_API_KEY", "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT", "GOOGLE_APPLICATION_CREDENTIALS",
];

/// `GIT_ENV_VARS` — overlay applied by [`get_git_env`] (ordered).
pub const GIT_ENV_VARS: &[(&str, &str)] = &[
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_ASKPASS", "true"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
];

/// `BASELINE_SEMGREP_PACKS` — always-included registry packs.
pub const BASELINE_SEMGREP_PACKS: &[(&str, &str)] = &[
    ("semgrep_security_audit", "p/security-audit"),
    ("semgrep_owasp_top_10", "p/owasp-top-ten"),
    ("semgrep_secrets", "p/secrets"),
];

// ───────────────────────── cycle injection ─────────────────────────────────

/// Push [`DANGEROUS_ENV_VARS`] into the security crate so `cc_trust`'s
/// dangerous-env detection matches the Python **config-present** path
/// (`_COMPREHENSIVE_DANGEROUS_ENV_VARS | MantishackConfig.DANGEROUS_ENV_VARS`).
/// Mirrors cc_trust.py's import-time union.
pub fn install_security_injection() {
    mantishack_core_security::cc_trust::set_config_dangerous_env_vars(
        DANGEROUS_ENV_VARS.iter().map(|s| s.to_string()).collect(),
    );
}

// ───────────────────────── get_safe_env family ─────────────────────────────

/// Read the current process environment as an ordered map.
fn current_env() -> EnvMap {
    std::env::vars().collect()
}

/// Dict-style upsert preserving insertion order (Python `dict[k] = v`).
fn set_in(env: &mut EnvMap, key: &str, value: &str) {
    if let Some(slot) = env.iter_mut().find(|(k, _)| k == key) {
        slot.1 = value.to_string();
    } else {
        env.push((key.to_string(), value.to_string()));
    }
}

/// Port of `get_safe_env` operating on an explicit ordered env (testable form).
///
/// Two-stage filter: allowlist (names + prefixes) then blocklist overlay
/// (proxy unless `preserve_proxy`, then dangerous vars). `include_python_user_base`
/// re-admits `PYTHONUSERBASE` verbatim from the source env after the strip.
/// `PYTHONUNBUFFERED=1` is always set last.
pub fn get_safe_env_from(
    source: &EnvMap,
    preserve_proxy: bool,
    include_python_user_base: bool,
) -> EnvMap {
    let mut env: EnvMap = source
        .iter()
        .filter(|(name, _)| {
            SAFE_ENV_ALLOWLIST.contains(&name.as_str())
                || SAFE_ENV_PREFIXES.iter().any(|p| name.starts_with(p))
        })
        .cloned()
        .collect();

    if !preserve_proxy {
        env = strip_env_vars(&env, PROXY_ENV_VARS);
    }
    env = strip_env_vars(&env, DANGEROUS_ENV_VARS);

    if include_python_user_base {
        if let Some((_, val)) = source.iter().find(|(n, _)| n == "PYTHONUSERBASE") {
            let val = val.clone();
            set_in(&mut env, "PYTHONUSERBASE", &val);
        }
    }
    set_in(&mut env, "PYTHONUNBUFFERED", "1");
    env
}

/// `get_safe_env()` against the real process environment.
pub fn get_safe_env(preserve_proxy: bool, include_python_user_base: bool) -> EnvMap {
    get_safe_env_from(&current_env(), preserve_proxy, include_python_user_base)
}

/// Port of `get_llm_env` on an explicit env (testable form).
pub fn get_llm_env_from(source: &EnvMap, include_python_user_base: bool) -> EnvMap {
    let mut env = get_safe_env_from(source, false, include_python_user_base);
    for var in LLM_API_KEY_VARS {
        if let Some((_, val)) = source.iter().find(|(n, _)| n == var) {
            if !val.is_empty() {
                let val = val.clone();
                set_in(&mut env, var, &val);
            }
        }
    }
    env
}

/// `get_llm_env()` against the real process environment.
pub fn get_llm_env(include_python_user_base: bool) -> EnvMap {
    get_llm_env_from(&current_env(), include_python_user_base)
}

/// Port of `get_git_env` on an explicit env (testable form).
pub fn get_git_env_from(source: &EnvMap) -> EnvMap {
    let mut env = get_safe_env_from(source, false, false);
    for (k, v) in GIT_ENV_VARS {
        set_in(&mut env, k, v);
    }
    env
}

/// `get_git_env()` against the real process environment.
pub fn get_git_env() -> EnvMap {
    get_git_env_from(&current_env())
}

// ───────────────────────── get_out_dir ─────────────────────────────────────

/// System-path prefixes [`get_out_dir`] refuses (matched on component boundary).
pub const FORBIDDEN_OUT_DIR_PREFIXES: &[&str] =
    &["/etc", "/usr", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys"];

/// Return the forbidden prefix a resolved path falls under, if any.
/// Component-boundary match (`/usr-local-foo` does not match `/usr`).
/// Port of the `get_out_dir` forbidden-prefix loop.
pub fn forbidden_system_prefix(resolved: &str) -> Option<&'static str> {
    for prefix in FORBIDDEN_OUT_DIR_PREFIXES {
        if resolved == *prefix || resolved.starts_with(&format!("{}/", prefix)) {
            return Some(prefix);
        }
    }
    None
}

/// Error returned by [`get_out_dir`] mirroring Python's `ValueError` paths.
#[derive(Debug, PartialEq)]
pub enum OutDirError {
    /// Resolves under a forbidden system prefix.
    SystemPath(String),
    /// Neither the path nor its parent exists (likely typo).
    ParentMissing(String),
}

/// Port of `get_out_dir`. `repo_root` supplies `BASE_OUT_DIR = repo_root/out`
/// (Python derives it from `__file__`; the installed crate takes it explicitly).
pub fn get_out_dir(repo_root: &std::path::Path) -> Result<PathBuf, OutDirError> {
    let base = std::env::var(ENV_OUT_DIR).unwrap_or_default();
    if base.is_empty() {
        return Ok(repo_root.join("out"));
    }
    let resolved = resolve_lexical(&base);
    let resolved_str = resolved.to_string_lossy().into_owned();
    if let Some(prefix) = forbidden_system_prefix(&resolved_str) {
        return Err(OutDirError::SystemPath(format!(
            "MANTISHACK_OUT_DIR={:?} resolves under system path {:?}",
            resolved_str, prefix
        )));
    }
    if !resolved.exists() && !resolved.parent().map(|p| p.exists()).unwrap_or(false) {
        return Err(OutDirError::ParentMissing(resolved_str));
    }
    Ok(resolved)
}

/// Non-strict path resolution akin to Python `Path.resolve()`: canonicalize if
/// the path exists, else absolutize against cwd.
fn resolve_lexical(base: &str) -> PathBuf {
    let p = std::path::Path::new(base);
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    }
}

// ───────────────────────── tuning-backed accessors ─────────────────────────

/// `MantishackConfig.MAX_SEMGREP_WORKERS` (driven by `tuning.json`).
pub fn max_semgrep_workers() -> i64 {
    mantishack_core_tuning::get_tuning().max_semgrep_workers
}
/// `MantishackConfig.MAX_CODEQL_WORKERS`.
pub fn max_codeql_workers() -> i64 {
    mantishack_core_tuning::get_tuning().max_codeql_workers
}
/// `MantishackConfig.CODEQL_RAM_MB`.
pub fn codeql_ram_mb() -> i64 {
    mantishack_core_tuning::get_tuning().codeql_ram_mb
}
/// `MantishackConfig.CODEQL_THREADS`.
pub fn codeql_threads() -> i64 {
    mantishack_core_tuning::get_tuning().codeql_threads
}

// ───────────────────────── PyO3 bindings ───────────────────────────────────

#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;
    use pyo3::types::{PyDict, PyModule};

    use mantishack_core_security::env_sanitisation::EnvMap;

    fn env_to_dict<'py>(py: Python<'py>, env: &EnvMap) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new_bound(py);
        for (k, v) in env {
            d.set_item(k, v)?;
        }
        Ok(d)
    }

    #[pyfunction]
    #[pyo3(signature = (preserve_proxy=false, include_python_user_base=false))]
    fn get_safe_env(
        py: Python<'_>,
        preserve_proxy: bool,
        include_python_user_base: bool,
    ) -> PyResult<Py<PyDict>> {
        let env = super::get_safe_env(preserve_proxy, include_python_user_base);
        Ok(env_to_dict(py, &env)?.unbind())
    }

    #[pyfunction]
    #[pyo3(signature = (include_python_user_base=false))]
    fn get_llm_env(py: Python<'_>, include_python_user_base: bool) -> PyResult<Py<PyDict>> {
        let env = super::get_llm_env(include_python_user_base);
        Ok(env_to_dict(py, &env)?.unbind())
    }

    #[pyfunction]
    fn get_git_env(py: Python<'_>) -> PyResult<Py<PyDict>> {
        let env = super::get_git_env();
        Ok(env_to_dict(py, &env)?.unbind())
    }

    /// `get_out_dir()` — resolves against `MANTISHACK_DIR`'s repo root.
    #[pyfunction]
    fn get_out_dir() -> PyResult<String> {
        let repo_root = std::env::var("MANTISHACK_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        match super::get_out_dir(&repo_root) {
            Ok(p) => Ok(p.to_string_lossy().into_owned()),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Install the dangerous-env injection into the security crate.
    #[pyfunction]
    fn install_security_injection() {
        super::install_security_injection();
    }

    #[pymodule]
    fn mantishack_core_config(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add("VERSION", super::VERSION)?;
        m.add_function(wrap_pyfunction!(get_safe_env, m)?)?;
        m.add_function(wrap_pyfunction!(get_llm_env, m)?)?;
        m.add_function(wrap_pyfunction!(get_git_env, m)?)?;
        m.add_function(wrap_pyfunction!(get_out_dir, m)?)?;
        m.add_function(wrap_pyfunction!(install_security_injection, m)?)?;
        Ok(())
    }
}

// ───────────────────────── tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn em(pairs: &[(&str, &str)]) -> EnvMap {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }
    fn sorted(env: &EnvMap) -> Vec<(String, String)> {
        let mut v = env.clone();
        v.sort();
        v
    }

    fn sample_env() -> EnvMap {
        em(&[
            ("PATH", "/usr/bin"), ("HOME", "/home/u"), ("TERMINAL", "xterm"),
            ("EDITOR", "vim"), ("LD_PRELOAD", "/e.so"), ("HTTP_PROXY", "http://p"),
            ("https_proxy", "http://q"), ("LC_CTYPE", "en"), ("LC_ALL", "C"),
            ("RANDOMVAR", "x"), ("PYTHONUSERBASE", "/pub"), ("ANTHROPIC_API_KEY", "sk-1"),
            ("FOO", "bar"), ("MANTISHACK_OUT_DIR", "/tmp/out"), ("VIRTUAL_ENV", "/venv"),
            ("TERM", "xterm-256color"),
        ])
    }

    #[test]
    fn safe_env_default_matches_python() {
        // Golden: keeps allowlisted/LC_*, strips proxy+dangerous, adds PYTHONUNBUFFERED.
        let got = sorted(&get_safe_env_from(&sample_env(), false, false));
        assert_eq!(got, em(&[
            ("HOME", "/home/u"), ("LC_ALL", "C"), ("LC_CTYPE", "en"),
            ("MANTISHACK_OUT_DIR", "/tmp/out"), ("PATH", "/usr/bin"),
            ("PYTHONUNBUFFERED", "1"), ("TERM", "xterm-256color"),
        ]));
    }

    #[test]
    fn safe_env_preserve_proxy_same_since_proxy_not_allowlisted() {
        // Golden: proxy vars aren't allowlisted, so preserve_proxy is a no-op here.
        let got = sorted(&get_safe_env_from(&sample_env(), true, false));
        assert_eq!(got, sorted(&get_safe_env_from(&sample_env(), false, false)));
    }

    #[test]
    fn safe_env_include_python_user_base_restores_it() {
        // Golden: PYTHONUSERBASE re-admitted after the dangerous-var strip.
        let got = sorted(&get_safe_env_from(&sample_env(), false, true));
        assert_eq!(got, em(&[
            ("HOME", "/home/u"), ("LC_ALL", "C"), ("LC_CTYPE", "en"),
            ("MANTISHACK_OUT_DIR", "/tmp/out"), ("PATH", "/usr/bin"),
            ("PYTHONUNBUFFERED", "1"), ("PYTHONUSERBASE", "/pub"),
            ("TERM", "xterm-256color"),
        ]));
    }

    #[test]
    fn llm_env_layers_api_keys() {
        // Golden: ANTHROPIC_API_KEY added on top of get_safe_env.
        let got = sorted(&get_llm_env_from(&sample_env(), false));
        assert_eq!(got, em(&[
            ("ANTHROPIC_API_KEY", "sk-1"), ("HOME", "/home/u"), ("LC_ALL", "C"),
            ("LC_CTYPE", "en"), ("MANTISHACK_OUT_DIR", "/tmp/out"), ("PATH", "/usr/bin"),
            ("PYTHONUNBUFFERED", "1"), ("TERM", "xterm-256color"),
        ]));
    }

    #[test]
    fn git_env_overlays_git_vars() {
        // Golden: GIT_ENV_VARS overlaid on get_safe_env.
        let got = sorted(&get_git_env_from(&sample_env()));
        assert_eq!(got, em(&[
            ("GIT_ASKPASS", "true"), ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_NOSYSTEM", "1"), ("GIT_CONFIG_SYSTEM", "/dev/null"),
            ("GIT_TERMINAL_PROMPT", "0"), ("HOME", "/home/u"), ("LC_ALL", "C"),
            ("LC_CTYPE", "en"), ("MANTISHACK_OUT_DIR", "/tmp/out"), ("PATH", "/usr/bin"),
            ("PYTHONUNBUFFERED", "1"), ("TERM", "xterm-256color"),
        ]));
    }

    #[test]
    fn pythonunbuffered_always_set_on_empty_env() {
        let got = get_safe_env_from(&em(&[]), false, false);
        assert_eq!(got, em(&[("PYTHONUNBUFFERED", "1")]));
    }

    #[test]
    fn forbidden_prefix_component_boundary() {
        // Golden: /usr/local/foo blocked under /usr; /usr-local-foo NOT.
        assert_eq!(forbidden_system_prefix("/usr/local/foo"), Some("/usr"));
        assert_eq!(forbidden_system_prefix("/etc"), Some("/etc"));
        assert_eq!(forbidden_system_prefix("/bin/x"), Some("/bin"));
        assert_eq!(forbidden_system_prefix("/usr-local-foo"), None);
        assert_eq!(forbidden_system_prefix("/home/u/out"), None);
        assert_eq!(forbidden_system_prefix("/proc/1"), Some("/proc"));
    }

    #[test]
    fn out_dir_defaults_to_repo_out_when_unset() {
        std::env::remove_var(ENV_OUT_DIR);
        let got = get_out_dir(std::path::Path::new("/repo")).unwrap();
        assert_eq!(got, PathBuf::from("/repo/out"));
    }

    #[test]
    fn constants_match_python() {
        assert_eq!(VERSION, "3.0.0");
        assert_eq!(DEFAULT_TIMEOUT, 1800);
        assert_eq!(CODEQL_ANALYZE_TIMEOUT, 2400);
        assert_eq!(RESOURCE_READ_LIMIT, 5 * 1024 * 1024);
        assert_eq!(ENV_OUT_DIR, "MANTISHACK_OUT_DIR");
        assert_eq!(SAFE_ENV_PREFIXES, &["LC_"]);
        assert_eq!(PROXY_ENV_VARS.len(), 6);
        assert_eq!(LLM_API_KEY_VARS.len(), 19);
        assert_eq!(SAFE_ENV_ALLOWLIST.len(), 27);
    }

    #[test]
    fn ollama_host_reads_env_late() {
        std::env::remove_var("OLLAMA_HOST");
        assert_eq!(ollama_host(), "http://localhost:11434");
        std::env::set_var("OLLAMA_HOST", "http://x:1");
        assert_eq!(ollama_host(), "http://x:1");
        std::env::remove_var("OLLAMA_HOST");
    }

    #[test]
    fn injection_makes_cc_trust_flag_config_only_vars() {
        use serde_json::json;
        // Before injection: TMPDIR (config-only) not flagged.
        mantishack_core_security::cc_trust::set_config_dangerous_env_vars(Vec::new());
        let v = json!({"env": {"TMPDIR": "/x"}});
        assert!(mantishack_core_security::cc_trust::scan_settings_value(&v).findings.is_empty());
        // After injection: flagged.
        install_security_injection();
        let fs = mantishack_core_security::cc_trust::scan_settings_value(&v);
        assert_eq!(fs.findings.len(), 1);
        assert_eq!(fs.findings[0].label, "env TMPDIR");
        mantishack_core_security::cc_trust::set_config_dangerous_env_vars(Vec::new());
    }
}
