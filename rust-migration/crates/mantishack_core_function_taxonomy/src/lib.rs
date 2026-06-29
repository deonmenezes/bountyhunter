//! Shared taxonomy of function-name categories with security significance.
//!
//! Faithful 1:1 port of `core/function_taxonomy/__init__.py`.  Every public
//! frozenset constant is exposed as a `&'static HashSet<&'static str>` via a
//! `OnceLock`-backed getter, and the `fortified()` helper is ported verbatim.
//!
//! Under the `python` feature the module also exports every symbol through
//! PyO3 so the Python orchestration layer can keep calling into this crate
//! transparently.

use std::collections::HashSet;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Bounded-string functions with classic overflow CVE shapes
// ---------------------------------------------------------------------------
static STRING_OVERFLOW_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn string_overflow_funcs() -> &'static HashSet<&'static str> {
    STRING_OVERFLOW_FUNCS_LOCK.get_or_init(|| {
        [
            // No bounds checking at all
            "strcpy", "strcat", "sprintf", "vsprintf",
            "gets",
            // Bounded but off-by-one / no-NUL-termination CVEs
            "strncpy", "strncat",
            // BSD variants
            "stpcpy", "stpncpy",
            // Wide-char variants
            "wcscpy", "wcsncpy", "wcscat", "wcsncat",
            // Windows ANSI/Unicode unsafe variants
            "lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// scanf-family parsing
// ---------------------------------------------------------------------------
static SCAN_FAMILY_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn scan_family_funcs() -> &'static HashSet<&'static str> {
    SCAN_FAMILY_FUNCS_LOCK.get_or_init(|| {
        [
            "scanf", "vscanf", "sscanf", "fscanf", "vsscanf", "vfscanf",
            "wscanf", "swscanf",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// Size-tainted memory copy operations
// ---------------------------------------------------------------------------
static MEMORY_COPY_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn memory_copy_funcs() -> &'static HashSet<&'static str> {
    MEMORY_COPY_FUNCS_LOCK.get_or_init(|| {
        ["memcpy", "memmove", "bcopy", "wmemcpy", "wmemmove"]
            .iter()
            .cloned()
            .collect()
    })
}

// ---------------------------------------------------------------------------
// Format-string sinks (rare/distinguishing only)
// ---------------------------------------------------------------------------
static FORMAT_STRING_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn format_string_funcs() -> &'static HashSet<&'static str> {
    FORMAT_STRING_FUNCS_LOCK.get_or_init(|| {
        [
            "vfprintf",
            "syslog",
            "snprintf", "vsnprintf",
            // BSD format-string wrappers
            "err", "errx", "warn", "warnx",
            // Apple equivalents
            "NSLog", "CFLog", "os_log", "os_log_with_type",
            // Windows ANSI/Unicode wsprintf
            "wsprintfA", "wsprintfW",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// Process execution / command injection sinks
// ---------------------------------------------------------------------------
static EXEC_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn exec_funcs() -> &'static HashSet<&'static str> {
    EXEC_FUNCS_LOCK.get_or_init(|| {
        [
            "system", "popen",
            "execl", "execv", "execlp", "execvp", "execle", "execve",
            "posix_spawn", "posix_spawnp",
            "fexecve", "execvpe",
            // Windows
            "CreateProcessA", "CreateProcessW",
            "CreateProcessAsUserA", "CreateProcessAsUserW",
            "CreateProcessWithLogonW",
            "ShellExecuteA", "ShellExecuteW",
            "ShellExecuteExA", "ShellExecuteExW",
            "WinExec",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// Size-tainted allocation
// ---------------------------------------------------------------------------
static ALLOC_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn alloc_funcs() -> &'static HashSet<&'static str> {
    ALLOC_FUNCS_LOCK.get_or_init(|| {
        [
            "calloc",
            "alloca",
            "posix_memalign", "aligned_alloc",
            "valloc", "memalign", "pvalloc",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// Network ingestion / server-side indicators
// ---------------------------------------------------------------------------
static NETWORK_INGEST_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn network_ingest_funcs() -> &'static HashSet<&'static str> {
    NETWORK_INGEST_FUNCS_LOCK.get_or_init(|| {
        [
            "recv", "recvfrom", "recvmsg", "recvmmsg",
            "accept", "bind", "listen",
            // OpenSSL
            "SSL_read", "BIO_read",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// Stream / file input (non-ubiquitous variants)
// ---------------------------------------------------------------------------
static STREAM_INPUT_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn stream_input_funcs() -> &'static HashSet<&'static str> {
    STREAM_INPUT_FUNCS_LOCK.get_or_init(|| {
        [
            "fgets", "fgetws",
            "getline", "getdelim",
            "pread", "preadv", "readv",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// Process boundary inputs (env)
// ---------------------------------------------------------------------------
static PROCESS_BOUNDARY_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn process_boundary_funcs() -> &'static HashSet<&'static str> {
    PROCESS_BOUNDARY_FUNCS_LOCK.get_or_init(|| ["getenv"].iter().cloned().collect())
}

// ---------------------------------------------------------------------------
// IPC primitives where less-privileged peers can write
// ---------------------------------------------------------------------------
static IPC_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn ipc_funcs() -> &'static HashSet<&'static str> {
    IPC_FUNCS_LOCK.get_or_init(|| {
        ["shmat", "shmget", "mq_receive", "mq_timedreceive", "msgrcv"]
            .iter()
            .cloned()
            .collect()
    })
}

// ---------------------------------------------------------------------------
// Kernel / userspace boundary (kernel-side only)
// ---------------------------------------------------------------------------
static KERNEL_USERSPACE_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn kernel_userspace_funcs() -> &'static HashSet<&'static str> {
    KERNEL_USERSPACE_FUNCS_LOCK.get_or_init(|| {
        [
            // Bare copies
            "copy_from_user", "_copy_from_user",
            "raw_copy_from_user", "__copy_from_user_inatomic",
            "get_user", "__get_user",
            "strncpy_from_user", "strnlen_user",
            // Allocator wrappers
            "memdup_user", "memdup_user_nul",
            "vmemdup_user",
            "strndup_user",
            // iovec / pages
            "import_iovec", "import_single_range",
            "_copy_from_iter", "copy_from_iter_full",
            "get_user_pages", "get_user_pages_fast",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// Device-control entry points (driver command interfaces)
// ---------------------------------------------------------------------------
static DEVICE_CONTROL_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn device_control_funcs() -> &'static HashSet<&'static str> {
    DEVICE_CONTROL_FUNCS_LOCK.get_or_init(|| {
        ["ioctl", "unlocked_ioctl", "compat_ioctl"]
            .iter()
            .cloned()
            .collect()
    })
}

// ---------------------------------------------------------------------------
// Process boundary markers (suid-context signal)
// ---------------------------------------------------------------------------
static PROCESS_BOUNDARY_MARKERS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn process_boundary_markers() -> &'static HashSet<&'static str> {
    PROCESS_BOUNDARY_MARKERS_LOCK.get_or_init(|| {
        ["secure_getenv", "getauxval"].iter().cloned().collect()
    })
}

// ---------------------------------------------------------------------------
// High-CVE-density parser entry points
// ---------------------------------------------------------------------------
static PARSER_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn parser_funcs() -> &'static HashSet<&'static str> {
    PARSER_FUNCS_LOCK.get_or_init(|| {
        [
            // Generic parser-generator output
            "yyparse",
            // XML — expat + libxml2
            "XML_Parse", "XML_ParseBuffer",
            "xmlReadMemory", "xmlReadDoc", "xmlReadFile",
            "xmlSAXUserParseMemory", "xmlParseDoc",
            // JSON — jansson, json-c, cJSON
            "json_loads", "json_loadb", "json_load_file",
            "json_object_from_file",
            "cJSON_Parse",
            // OpenSSL ASN.1
            "d2i_X509", "d2i_X509_bio",
            "d2i_PrivateKey",
            // OpenSSL PEM
            "PEM_read_X509", "PEM_read_PrivateKey",
            "PEM_read_bio_X509", "PEM_read_bio_PrivateKey",
            // Embedded scripting
            "lua_load", "lua_loadbuffer",
            "luaL_loadstring", "luaL_dostring", "luaL_dofile",
            "Py_CompileString", "PyRun_String", "PyRun_File",
            // Image format parsers
            "png_read_info", "png_read_image",
            "jpeg_read_header", "jpeg_read_scanlines",
            "TIFFOpen", "TIFFReadDirectory",
            "WebPDecode", "WebPDecodeRGBA", "WebPDecodeBGRA",
            // Compression library decoders
            "inflate",
            "BZ2_bzDecompress",
            "lzma_code",
            "LZ4_decompress_safe", "LZ4_decompress_fast",
            "ZSTD_decompress", "ZSTD_decompressStream",
            "BrotliDecoderDecompress", "BrotliDecoderDecompressStream",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// Integer parsing (CWE-190 / -191 hints)
// ---------------------------------------------------------------------------
static INTEGER_PARSE_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn integer_parse_funcs() -> &'static HashSet<&'static str> {
    INTEGER_PARSE_FUNCS_LOCK.get_or_init(|| {
        [
            "atoi", "atol", "atoll",
            "strtoul", "strtol", "strtoull", "strtoll",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// TOCTOU + path-traversal pattern markers
// ---------------------------------------------------------------------------
static TOCTOU_FUNCS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn toctou_funcs() -> &'static HashSet<&'static str> {
    TOCTOU_FUNCS_LOCK.get_or_init(|| {
        [
            "access", "faccessat",
            "realpath", "readlink", "readlinkat",
            "chroot",
            "mktemp", "tempnam",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// macOS Swift / Objective-C dangerous symbols (substring match semantics)
// ---------------------------------------------------------------------------
static MACOS_DANGEROUS_SUBSTRINGS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn macos_dangerous_substrings() -> &'static HashSet<&'static str> {
    MACOS_DANGEROUS_SUBSTRINGS_LOCK.get_or_init(|| {
        [
            // CoreFoundation parsers
            "CFPropertyListCreateWithData", "CFPropertyListCreateFromXMLData",
            "CFReadStreamRead", "CFDataGetBytes",
            "CFStringCreateWithBytes", "CFURLCreateWithBytes",
            "CFXMLParserCreate", "CFXMLTreeCreateFromData",
            // Swift Foundation parsing / IO entry points
            "Foundation.Data.contentsOf",
            "Foundation.Data.base64Encoded",
            "Foundation.Data.write",
            "Foundation.Data.Iterator",
            "Foundation.URL.fileURLWithPath",
            "Foundation.URL.absoluteString",
            "Foundation.JSONSerialization",
            "Foundation.PropertyListSerialization",
            "Foundation.PropertyListDecoder",
            "Foundation.JSONDecoder",
            // Apple security framework / keychain
            "SecPolicyCreateSSL",
            "SecTrustEvaluate",
            "SecItemCopyMatching",
            "SecKeychainItem",
            // NSData / NSString interop
            "NSDataReadingOptions",
            "NSDataBase64DecodingOptions",
            "NSStringFromBytes",
            // Process execution via Foundation
            "NSTask",
            "Foundation.Process",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// Entry-point name exact matches
// ---------------------------------------------------------------------------
static ENTRY_POINT_HINTS_LOCK: OnceLock<HashSet<&'static str>> = OnceLock::new();
pub fn entry_point_hints() -> &'static HashSet<&'static str> {
    ENTRY_POINT_HINTS_LOCK.get_or_init(|| {
        [
            "main", "_start", "wmain",
            "WinMain", "DllMain", "DriverEntry",
            "LLVMFuzzerTestOneInput",
            "do_main",
        ]
        .iter()
        .cloned()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// fortified() helper
//
// Return the FORTIFY_SOURCE __*_chk variants of every function in `base`.
// Mirrors: `frozenset(f"__{name}_chk" for name in base)`
// ---------------------------------------------------------------------------
pub fn fortified(base: &HashSet<&str>) -> HashSet<String> {
    base.iter().map(|name| format!("__{name}_chk")).collect()
}

/// Owned-string variant — matches the Python calling convention where the
/// input set may contain owned strings (e.g. from a PyO3 call).
pub fn fortified_owned(base: &HashSet<String>) -> HashSet<String> {
    base.iter().map(|name| format!("__{name}_chk")).collect()
}

// ---------------------------------------------------------------------------
// PyO3 bindings (feature-gated)
// ---------------------------------------------------------------------------
#[cfg(feature = "python")]
mod python {
    use super::*;
    use pyo3::prelude::*;
    use pyo3::types::PyFrozenSet;

    /// Convert a Rust `HashSet<&str>` into a Python `frozenset`.
    fn to_py_frozenset<'py>(
        py: Python<'py>,
        set: &HashSet<&'static str>,
    ) -> PyResult<Bound<'py, PyFrozenSet>> {
        PyFrozenSet::new(py, set.iter().copied())
    }

    /// Python-callable `fortified(base)` — mirrors `def fortified(base: FrozenSet[str]) -> FrozenSet[str]`.
    #[pyfunction]
    fn fortified_py<'py>(
        py: Python<'py>,
        base: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyFrozenSet>> {
        // Accept any iterable of strings (frozenset, set, list, …)
        let owned: HashSet<String> = base
            .iter()?
            .map(|item| item.and_then(|i| i.extract::<String>()))
            .collect::<PyResult<_>>()?;
        let result = super::fortified_owned(&owned);
        PyFrozenSet::new(py, result.iter().map(|s| s.as_str()))
    }

    #[pymodule]
    pub fn mantishack_core_function_taxonomy(m: &Bound<'_, PyModule>) -> PyResult<()> {
        let py = m.py();

        m.add("STRING_OVERFLOW_FUNCS",  to_py_frozenset(py, super::string_overflow_funcs())?)?;
        m.add("SCAN_FAMILY_FUNCS",      to_py_frozenset(py, super::scan_family_funcs())?)?;
        m.add("MEMORY_COPY_FUNCS",      to_py_frozenset(py, super::memory_copy_funcs())?)?;
        m.add("FORMAT_STRING_FUNCS",    to_py_frozenset(py, super::format_string_funcs())?)?;
        m.add("EXEC_FUNCS",             to_py_frozenset(py, super::exec_funcs())?)?;
        m.add("ALLOC_FUNCS",            to_py_frozenset(py, super::alloc_funcs())?)?;
        m.add("NETWORK_INGEST_FUNCS",   to_py_frozenset(py, super::network_ingest_funcs())?)?;
        m.add("STREAM_INPUT_FUNCS",     to_py_frozenset(py, super::stream_input_funcs())?)?;
        m.add("PROCESS_BOUNDARY_FUNCS", to_py_frozenset(py, super::process_boundary_funcs())?)?;
        m.add("IPC_FUNCS",              to_py_frozenset(py, super::ipc_funcs())?)?;
        m.add("KERNEL_USERSPACE_FUNCS", to_py_frozenset(py, super::kernel_userspace_funcs())?)?;
        m.add("DEVICE_CONTROL_FUNCS",   to_py_frozenset(py, super::device_control_funcs())?)?;
        m.add("PROCESS_BOUNDARY_MARKERS", to_py_frozenset(py, super::process_boundary_markers())?)?;
        m.add("PARSER_FUNCS",           to_py_frozenset(py, super::parser_funcs())?)?;
        m.add("INTEGER_PARSE_FUNCS",    to_py_frozenset(py, super::integer_parse_funcs())?)?;
        m.add("TOCTOU_FUNCS",           to_py_frozenset(py, super::toctou_funcs())?)?;
        m.add("MACOS_DANGEROUS_SUBSTRINGS", to_py_frozenset(py, super::macos_dangerous_substrings())?)?;
        m.add("ENTRY_POINT_HINTS",      to_py_frozenset(py, super::entry_point_hints())?)?;

        m.add_function(wrap_pyfunction!(fortified_py, m)?)?;

        Ok(())
    }
}

#[cfg(feature = "python")]
pub use python::mantishack_core_function_taxonomy;

// ---------------------------------------------------------------------------
// Tests — golden vectors from Python oracle
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Golden case 1: sizes match Python frozenset len()
    // -----------------------------------------------------------------------
    #[test]
    fn test_set_sizes() {
        assert_eq!(string_overflow_funcs().len(),      17);
        assert_eq!(scan_family_funcs().len(),           8);
        assert_eq!(memory_copy_funcs().len(),           5);
        assert_eq!(format_string_funcs().len(),        14);
        assert_eq!(exec_funcs().len(),                 22);
        assert_eq!(alloc_funcs().len(),                 7);
        assert_eq!(network_ingest_funcs().len(),        9);
        assert_eq!(stream_input_funcs().len(),          7);
        assert_eq!(process_boundary_funcs().len(),      1);
        assert_eq!(ipc_funcs().len(),                   5);
        assert_eq!(kernel_userspace_funcs().len(),     18);
        assert_eq!(device_control_funcs().len(),        3);
        assert_eq!(process_boundary_markers().len(),    2);
        assert_eq!(parser_funcs().len(),               46);
        assert_eq!(integer_parse_funcs().len(),         7);
        assert_eq!(toctou_funcs().len(),                8);
        assert_eq!(macos_dangerous_substrings().len(), 27);
        assert_eq!(entry_point_hints().len(),           8);
    }

    // -----------------------------------------------------------------------
    // Golden case 2: STRING_OVERFLOW_FUNCS membership
    // -----------------------------------------------------------------------
    #[test]
    fn test_string_overflow_funcs_membership() {
        let s = string_overflow_funcs();
        assert!(s.contains("strcpy"));
        assert!(s.contains("strncpy"));
        assert!(s.contains("gets"));
        assert!(s.contains("wcsncpy"));
        assert!(s.contains("lstrcpyA"));
        assert!(s.contains("lstrcatW"));
        // snprintf lives in FORMAT_STRING_FUNCS per policy
        assert!(!s.contains("snprintf"));
        assert!(!s.contains("vsnprintf"));
        assert!(!s.contains("malloc"));
    }

    // -----------------------------------------------------------------------
    // Golden case 3: FORMAT_STRING_FUNCS — snprintf lives here, not in overflow
    // -----------------------------------------------------------------------
    #[test]
    fn test_format_string_funcs_membership() {
        let s = format_string_funcs();
        assert!(s.contains("snprintf"));
        assert!(s.contains("vsnprintf"));
        assert!(s.contains("vfprintf"));
        assert!(s.contains("syslog"));
        assert!(s.contains("NSLog"));
        assert!(s.contains("os_log_with_type"));
        assert!(s.contains("wsprintfA"));
        // ubiquitous — excluded per policy
        assert!(!s.contains("printf"));
        assert!(!s.contains("fprintf"));
    }

    // -----------------------------------------------------------------------
    // Golden case 4: EXEC_FUNCS — POSIX + Windows
    // -----------------------------------------------------------------------
    #[test]
    fn test_exec_funcs_membership() {
        let s = exec_funcs();
        assert!(s.contains("system"));
        assert!(s.contains("WinExec"));
        assert!(s.contains("execve"));
        assert!(s.contains("posix_spawn"));
        assert!(s.contains("ShellExecuteExW"));
        assert!(s.contains("CreateProcessWithLogonW"));
        assert!(!s.contains("fork"));
    }

    // -----------------------------------------------------------------------
    // Golden case 5: ALLOC_FUNCS — malloc excluded, calloc included
    // -----------------------------------------------------------------------
    #[test]
    fn test_alloc_funcs_membership() {
        let s = alloc_funcs();
        assert!(s.contains("calloc"));
        assert!(s.contains("alloca"));
        assert!(s.contains("pvalloc"));
        assert!(!s.contains("malloc"));
        assert!(!s.contains("realloc"));
    }

    // -----------------------------------------------------------------------
    // Golden case 6: NETWORK_INGEST_FUNCS
    // -----------------------------------------------------------------------
    #[test]
    fn test_network_ingest_funcs_membership() {
        let s = network_ingest_funcs();
        assert!(s.contains("recv"));
        assert!(s.contains("SSL_read"));
        assert!(s.contains("BIO_read"));
        assert!(s.contains("recvmmsg"));
        assert!(!s.contains("read")); // ubiquitous
        assert!(!s.contains("send"));
    }

    // -----------------------------------------------------------------------
    // Golden case 7: KERNEL_USERSPACE_FUNCS — underscore variants present
    // -----------------------------------------------------------------------
    #[test]
    fn test_kernel_userspace_funcs_membership() {
        let s = kernel_userspace_funcs();
        assert!(s.contains("copy_from_user"));
        assert!(s.contains("_copy_from_user"));
        assert!(s.contains("__copy_from_user_inatomic"));
        assert!(s.contains("get_user_pages_fast"));
        assert!(s.contains("memdup_user_nul"));
        assert!(s.contains("_copy_from_iter"));
        assert!(!s.contains("copy_to_user"));
    }

    // -----------------------------------------------------------------------
    // Golden case 8: PARSER_FUNCS — diverse entries
    // -----------------------------------------------------------------------
    #[test]
    fn test_parser_funcs_membership() {
        let s = parser_funcs();
        assert!(s.contains("yyparse"));
        assert!(s.contains("cJSON_Parse"));
        assert!(s.contains("ZSTD_decompress"));
        assert!(s.contains("BrotliDecoderDecompress"));
        assert!(s.contains("BrotliDecoderDecompressStream"));
        assert!(s.contains("lua_loadbuffer"));
        assert!(s.contains("WebPDecodeBGRA"));
        assert!(s.contains("d2i_X509_bio"));
        assert!(s.contains("PEM_read_bio_PrivateKey"));
        assert!(!s.contains("malloc"));
        assert!(!s.contains("fopen"));
    }

    // -----------------------------------------------------------------------
    // Golden case 9: MACOS_DANGEROUS_SUBSTRINGS
    // -----------------------------------------------------------------------
    #[test]
    fn test_macos_dangerous_substrings_membership() {
        let s = macos_dangerous_substrings();
        assert!(s.contains("Foundation.JSONDecoder"));
        assert!(s.contains("NSTask"));
        assert!(s.contains("Foundation.Process"));
        assert!(s.contains("CFXMLTreeCreateFromData"));
        assert!(s.contains("SecKeychainItem"));
        assert!(s.contains("NSDataBase64DecodingOptions"));
        // NSLog is in FORMAT_STRING_FUNCS, not here
        assert!(!s.contains("NSLog"));
    }

    // -----------------------------------------------------------------------
    // Golden case 10: PROCESS_BOUNDARY_FUNCS vs PROCESS_BOUNDARY_MARKERS
    // -----------------------------------------------------------------------
    #[test]
    fn test_process_boundary_separation() {
        let funcs = process_boundary_funcs();
        let markers = process_boundary_markers();
        assert!(funcs.contains("getenv"));
        assert!(!funcs.contains("secure_getenv"));
        assert!(markers.contains("secure_getenv"));
        assert!(markers.contains("getauxval"));
        assert!(!markers.contains("getenv"));
    }

    // -----------------------------------------------------------------------
    // Golden case 11: fortified() — pure function tests
    // -----------------------------------------------------------------------
    #[test]
    fn test_fortified_single() {
        let base: HashSet<&str> = ["strcpy"].iter().cloned().collect();
        let result = fortified(&base);
        assert_eq!(result.len(), 1);
        assert!(result.contains("__strcpy_chk"));
        assert!(!result.contains("strcpy"));
    }

    #[test]
    fn test_fortified_two_elems() {
        let base: HashSet<&str> = ["strcpy", "strcat"].iter().cloned().collect();
        let result = fortified(&base);
        assert_eq!(result.len(), 2);
        assert!(result.contains("__strcpy_chk"));
        assert!(result.contains("__strcat_chk"));
    }

    #[test]
    fn test_fortified_empty() {
        let base: HashSet<&str> = HashSet::new();
        let result = fortified(&base);
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // Golden case 12: fortified(STRING_OVERFLOW_FUNCS) — full output verified
    // against Python oracle:
    //   sorted(t.fortified(t.STRING_OVERFLOW_FUNCS)) →
    //   ['__gets_chk', '__lstrcatA_chk', '__lstrcatW_chk', '__lstrcpyA_chk',
    //    '__lstrcpyW_chk', '__sprintf_chk', '__stpcpy_chk', '__stpncpy_chk',
    //    '__strcat_chk', '__strcpy_chk', '__strncat_chk', '__strncpy_chk',
    //    '__vsprintf_chk', '__wcscat_chk', '__wcscpy_chk', '__wcsncat_chk',
    //    '__wcsncpy_chk']
    // -----------------------------------------------------------------------
    #[test]
    fn test_fortified_string_overflow_full() {
        let result = fortified(string_overflow_funcs());
        assert_eq!(result.len(), 17);
        for e in &[
            "__gets_chk",
            "__lstrcatA_chk",
            "__lstrcatW_chk",
            "__lstrcpyA_chk",
            "__lstrcpyW_chk",
            "__sprintf_chk",
            "__stpcpy_chk",
            "__stpncpy_chk",
            "__strcat_chk",
            "__strcpy_chk",
            "__strncat_chk",
            "__strncpy_chk",
            "__vsprintf_chk",
            "__wcscat_chk",
            "__wcscpy_chk",
            "__wcsncat_chk",
            "__wcsncpy_chk",
        ] {
            assert!(result.contains(*e), "missing {e}");
        }
    }

    // -----------------------------------------------------------------------
    // Golden case 13: fortified(MEMORY_COPY_FUNCS) — spot checks
    // -----------------------------------------------------------------------
    #[test]
    fn test_fortified_memory_copy() {
        let result = fortified(memory_copy_funcs());
        assert!(result.contains("__memcpy_chk"));
        assert!(result.contains("__memmove_chk"));
        assert!(result.contains("__wmemcpy_chk"));
        assert_eq!(result.len(), 5);
    }

    // -----------------------------------------------------------------------
    // Golden case 14: fortified(FORMAT_STRING_FUNCS) — snprintf included
    // -----------------------------------------------------------------------
    #[test]
    fn test_fortified_format_string() {
        let result = fortified(format_string_funcs());
        assert!(result.contains("__snprintf_chk"));
        assert!(result.contains("__vsnprintf_chk"));
        assert!(result.contains("__syslog_chk"));
        assert_eq!(result.len(), 14);
    }

    // -----------------------------------------------------------------------
    // Golden case 15: TOCTOU_FUNCS — BANNED temp-file APIs present
    // -----------------------------------------------------------------------
    #[test]
    fn test_toctou_funcs_membership() {
        let s = toctou_funcs();
        assert!(s.contains("mktemp"));
        assert!(s.contains("tempnam"));
        assert!(s.contains("access"));
        assert!(s.contains("faccessat"));
        assert!(s.contains("chroot"));
        assert!(s.contains("readlinkat"));
        // race-free variants NOT present
        assert!(!s.contains("tmpfile"));
        assert!(!s.contains("mkstemp"));
    }

    // -----------------------------------------------------------------------
    // Golden case 16: ENTRY_POINT_HINTS
    // -----------------------------------------------------------------------
    #[test]
    fn test_entry_point_hints_membership() {
        let s = entry_point_hints();
        assert!(s.contains("main"));
        assert!(s.contains("_start"));
        assert!(s.contains("LLVMFuzzerTestOneInput"));
        assert!(s.contains("do_main"));
        assert!(s.contains("DriverEntry"));
        assert!(s.contains("DllMain"));
        // suffix patterns handled by consumer, not here
        assert!(!s.contains("_main"));
    }

    // -----------------------------------------------------------------------
    // Golden case 17: gets() in STRING_OVERFLOW_FUNCS, NOT in STREAM_INPUT_FUNCS
    // (categories are disjoint per policy)
    // -----------------------------------------------------------------------
    #[test]
    fn test_gets_not_in_stream_input() {
        assert!(string_overflow_funcs().contains("gets"));
        assert!(!stream_input_funcs().contains("gets"));
    }

    // -----------------------------------------------------------------------
    // Golden case 18: INTEGER_PARSE_FUNCS — no float parsers
    // -----------------------------------------------------------------------
    #[test]
    fn test_integer_parse_funcs() {
        let s = integer_parse_funcs();
        assert!(s.contains("atoi"));
        assert!(s.contains("atoll"));
        assert!(s.contains("strtoll"));
        assert!(s.contains("strtoull"));
        // float parsers excluded per policy
        assert!(!s.contains("atof"));
        assert!(!s.contains("strtod"));
        assert!(!s.contains("strtof"));
    }
}
