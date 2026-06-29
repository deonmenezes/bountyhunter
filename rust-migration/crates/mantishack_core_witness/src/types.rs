//! Witness data model — typed records for triggering inputs.
//!
//! Faithful Rust port of core/witness/types.py.
//!
//! A `Witness` is the canonical record that captures the bytes a pipeline
//! observed (or attempted) triggering a bug with. `WitnessSource` names
//! which pipeline produced the record; `WitnessOutcome` is the normalised
//! label across pipelines.
//!
//! **Serialisation contract**: `to_dict()` / `from_dict()` round-trip
//! faithfully. Field ordering in the JSON object matches Python's
//! insertion order so cross-language consumers see the same layout.
//!
//! **Hash invariant**: `bytes_hash` must be a 64-char lowercase hex
//! SHA-256 digest. The constructor rejects shorter/longer/non-hex strings
//! with a `WitnessTypeError` mirroring Python's `ValueError`.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Error type for `Witness` construction and `from_dict` failures.
#[derive(Debug)]
pub struct WitnessTypeError(pub String);

impl std::fmt::Display for WitnessTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WitnessTypeError {}

// ── WitnessSource ─────────────────────────────────────────────────────────────

/// Which pipeline produced this witness.
///
/// String values are persisted-data contracts — changing them invalidates
/// every existing manifest. They match the Python `WitnessSource` enum values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessSource {
    /// AFL++ fuzz corpus crash.
    Fuzz,
    /// /crash-analysis debugger replay of a fuzz crash.
    CrashReplay,
    /// /validate Stage A/B PoC execution.
    ValidateSkillPoc,
    /// LLM-emitted exploit code run (future / placeholder).
    LlmEmitRun,
    /// Operator-supplied known-good PoC.
    Manual,
}

impl WitnessSource {
    /// The canonical string value persisted in JSON manifests.
    pub fn as_str(&self) -> &'static str {
        match self {
            WitnessSource::Fuzz => "fuzz",
            WitnessSource::CrashReplay => "crash_replay",
            WitnessSource::ValidateSkillPoc => "validate_skill_poc",
            WitnessSource::LlmEmitRun => "llm_emit_run",
            WitnessSource::Manual => "manual",
        }
    }

    /// Parse from a persisted string value. Rejects unknown values.
    pub fn from_value(s: &str) -> Result<Self, WitnessTypeError> {
        match s {
            "fuzz" => Ok(WitnessSource::Fuzz),
            "crash_replay" => Ok(WitnessSource::CrashReplay),
            "validate_skill_poc" => Ok(WitnessSource::ValidateSkillPoc),
            "llm_emit_run" => Ok(WitnessSource::LlmEmitRun),
            "manual" => Ok(WitnessSource::Manual),
            other => Err(WitnessTypeError(format!(
                "'{}' is not a valid WitnessSource",
                other
            ))),
        }
    }
}

impl std::fmt::Display for WitnessSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── WitnessOutcome ────────────────────────────────────────────────────────────

/// What was observed when the target ran on the witness bytes.
///
/// Normalised across pipelines; pipeline-specific detail goes into
/// `Witness::outcome_detail`. String values are persisted-data contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessOutcome {
    /// Bytes captured but target not executed.
    NotRun,
    /// Target ran to completion without an obvious bug trigger.
    NoObviousEffect,
    /// Target killed by a signal (SIGSEGV, SIGABRT, SIGBUS, etc.).
    ExitSignal,
    /// AddressSanitizer / UBSan / MSan emitted a diagnostic.
    SanitizerReport,
    /// ExploitGym-style success: the witness achieved the benchmark's
    /// defined success condition (flag read).
    FlagCaptured,
    /// Producer doesn't know how the run terminated.
    Unknown,
}

impl WitnessOutcome {
    /// The canonical string value persisted in JSON manifests.
    pub fn as_str(&self) -> &'static str {
        match self {
            WitnessOutcome::NotRun => "not_run",
            WitnessOutcome::NoObviousEffect => "no_obvious_effect",
            WitnessOutcome::ExitSignal => "exit_signal",
            WitnessOutcome::SanitizerReport => "sanitizer_report",
            WitnessOutcome::FlagCaptured => "flag_captured",
            WitnessOutcome::Unknown => "unknown",
        }
    }

    /// Parse from a persisted string value. Rejects unknown values.
    pub fn from_value(s: &str) -> Result<Self, WitnessTypeError> {
        match s {
            "not_run" => Ok(WitnessOutcome::NotRun),
            "no_obvious_effect" => Ok(WitnessOutcome::NoObviousEffect),
            "exit_signal" => Ok(WitnessOutcome::ExitSignal),
            "sanitizer_report" => Ok(WitnessOutcome::SanitizerReport),
            "flag_captured" => Ok(WitnessOutcome::FlagCaptured),
            "unknown" => Ok(WitnessOutcome::Unknown),
            other => Err(WitnessTypeError(format!(
                "'{}' is not a valid WitnessOutcome",
                other
            ))),
        }
    }
}

impl std::fmt::Display for WitnessOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Witness ───────────────────────────────────────────────────────────────────

/// A typed record of "these bytes triggered this outcome on this target."
///
/// Fields mirror the Python dataclass exactly. Use `Witness::new` for the
/// common case (required fields only) or construct the struct directly to
/// set optional fields. Call `validate_hash` on the bytes_hash before
/// constructing if you bypass `new`.
#[derive(Debug, Clone)]
pub struct Witness {
    /// SHA-256 hex digest of the actual bytes. 64 chars, lowercase hex.
    pub bytes_hash: String,
    /// Which pipeline produced this record.
    pub source: WitnessSource,
    /// Normalised outcome label.
    pub observed_outcome: WitnessOutcome,
    /// Length of the raw bytes (0 = not set; store stamps it on `put`).
    pub bytes_len: usize,
    /// SHA-256 of the target binary at time of observation. Optional.
    pub target_binary_hash: Option<String>,
    /// SHA-256 of the target source tree at time of observation. Optional.
    pub target_source_hash: Option<String>,
    /// Pipeline-specific detail blob. Must be JSON-serialisable.
    pub outcome_detail: HashMap<String, Value>,
    /// Model / tool that produced the record. Optional.
    pub produced_by: Option<String>,
    /// When the record was created (UTC).
    pub timestamp: DateTime<Utc>,
}

fn validate_hash_str(h: &str) -> Result<(), WitnessTypeError> {
    if h.len() != 64 {
        let preview = &h[..h.len().min(16)];
        return Err(WitnessTypeError(format!(
            "bytes_hash must be a 64-char SHA-256 hex digest, got {} chars: {:?}...",
            h.len(),
            preview
        )));
    }
    if !h.chars().all(|c| c.is_ascii_hexdigit()) {
        let preview = &h[..16];
        return Err(WitnessTypeError(format!(
            "bytes_hash must be hex, got {:?}...",
            preview
        )));
    }
    Ok(())
}

impl Witness {
    /// Construct with required fields only; optional fields take defaults.
    ///
    /// Rejects an invalid `bytes_hash` (not 64-char lowercase hex).
    pub fn new(
        bytes_hash: String,
        source: WitnessSource,
        observed_outcome: WitnessOutcome,
    ) -> Result<Self, WitnessTypeError> {
        validate_hash_str(&bytes_hash)?;
        Ok(Witness {
            bytes_hash,
            source,
            observed_outcome,
            bytes_len: 0,
            target_binary_hash: None,
            target_source_hash: None,
            outcome_detail: HashMap::new(),
            produced_by: None,
            timestamp: Utc::now(),
        })
    }

    /// JSON-safe serialisation. Mirrors `Witness.to_dict()` in Python exactly:
    /// - `datetime` → ISO 8601 string with `+00:00` offset (not `Z`)
    /// - enums → their string `value`
    /// - optional fields → `null` when absent
    ///
    /// Field insertion order matches Python's `to_dict` for layout parity.
    pub fn to_dict(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "bytes_hash".to_string(),
            Value::String(self.bytes_hash.clone()),
        );
        map.insert(
            "bytes_len".to_string(),
            Value::Number(self.bytes_len.into()),
        );
        map.insert(
            "source".to_string(),
            Value::String(self.source.as_str().to_string()),
        );
        map.insert(
            "observed_outcome".to_string(),
            Value::String(self.observed_outcome.as_str().to_string()),
        );
        map.insert(
            "target_binary_hash".to_string(),
            self.target_binary_hash
                .as_ref()
                .map(|h| Value::String(h.clone()))
                .unwrap_or(Value::Null),
        );
        map.insert(
            "target_source_hash".to_string(),
            self.target_source_hash
                .as_ref()
                .map(|h| Value::String(h.clone()))
                .unwrap_or(Value::Null),
        );
        let detail_obj: Map<String, Value> = self
            .outcome_detail
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        map.insert("outcome_detail".to_string(), Value::Object(detail_obj));
        map.insert(
            "produced_by".to_string(),
            self.produced_by
                .as_ref()
                .map(|p| Value::String(p.clone()))
                .unwrap_or(Value::Null),
        );
        // Use "+00:00" suffix (not "Z") to match Python's isoformat() output.
        // Truncate to seconds precision so whole-second timestamps round-trip
        // identically to Python's datetime.isoformat().
        let ts_str = self.timestamp.format("%Y-%m-%dT%H:%M:%S%:z").to_string();
        map.insert("timestamp".to_string(), Value::String(ts_str));
        Value::Object(map)
    }

    /// Inverse of `to_dict`. Tolerant of extra keys (dropped silently).
    ///
    /// Missing optional keys default as in Python:
    /// - `bytes_len` → 0
    /// - `target_binary_hash`, `target_source_hash`, `produced_by` → None
    /// - `outcome_detail` → empty map
    /// - `timestamp` → current UTC time
    ///
    /// Raises `WitnessTypeError` for:
    /// - missing required fields (`bytes_hash`, `source`, `observed_outcome`)
    /// - unrecognised enum values
    /// - invalid `bytes_hash` format
    pub fn from_dict(data: &Value) -> Result<Self, WitnessTypeError> {
        let obj = data.as_object().ok_or_else(|| {
            WitnessTypeError("Witness.from_dict: expected a JSON object".to_string())
        })?;

        let bytes_hash = obj
            .get("bytes_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                WitnessTypeError("missing required field: bytes_hash".to_string())
            })?
            .to_string();

        let bytes_len = obj
            .get("bytes_len")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        let source = WitnessSource::from_value(
            obj.get("source")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    WitnessTypeError("missing required field: source".to_string())
                })?,
        )?;

        let observed_outcome = WitnessOutcome::from_value(
            obj.get("observed_outcome")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    WitnessTypeError("missing required field: observed_outcome".to_string())
                })?,
        )?;

        let target_binary_hash = obj
            .get("target_binary_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let target_source_hash = obj
            .get("target_source_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Python: dict(data.get("outcome_detail") or {})
        // "or {}" handles null → treat as empty map.
        let outcome_detail: HashMap<String, Value> = obj
            .get("outcome_detail")
            .and_then(|v| v.as_object())
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        let produced_by = obj
            .get("produced_by")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Python: if isinstance(ts_raw, str): datetime.fromisoformat(ts_raw)
        //         elif isinstance(ts_raw, datetime): ts_raw
        //         else: datetime.now(timezone.utc)
        let timestamp = match obj.get("timestamp") {
            Some(Value::String(s)) => chrono::DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            _ => Utc::now(),
        };

        // Validate hash last (matches Python's __post_init__ order).
        validate_hash_str(&bytes_hash)?;

        Ok(Witness {
            bytes_hash,
            bytes_len,
            source,
            observed_outcome,
            target_binary_hash,
            target_source_hash,
            outcome_detail,
            produced_by,
            timestamp,
        })
    }
}

// ── compute_bytes_hash ────────────────────────────────────────────────────────

/// SHA-256 hex digest of `data`.
///
/// Single helper so all producers compute the hash consistently.
/// Matches Python's `hashlib.sha256(data).hexdigest()` exactly —
/// lowercase hex, no separators, 64 characters.
pub fn compute_bytes_hash(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        write!(acc, "{:02x}", b).expect("write to String is infallible");
        acc
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const VALID_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // -- Golden vector: compute_bytes_hash --

    #[test]
    fn test_compute_bytes_hash_empty() {
        // Python: hashlib.sha256(b"").hexdigest()
        // → "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert_eq!(
            compute_bytes_hash(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_compute_bytes_hash_hello_world() {
        // Python: hashlib.sha256(b"hello world").hexdigest()
        // → "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert_eq!(
            compute_bytes_hash(b"hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_bytes_hash_known_bytes() {
        // Python: hashlib.sha256(b"\x00\xff\x42\xab").hexdigest()
        // → "ff92a7fbe020274aaa274b17e13a098350f77889824df2ce39f35faa29c6a9cb"
        assert_eq!(
            compute_bytes_hash(&[0x00, 0xff, 0x42, 0xab]),
            "ff92a7fbe020274aaa274b17e13a098350f77889824df2ce39f35faa29c6a9cb"
        );
    }

    // -- Enum value stability (golden) --

    #[test]
    fn test_witness_source_string_values_stable() {
        assert_eq!(WitnessSource::Fuzz.as_str(), "fuzz");
        assert_eq!(WitnessSource::CrashReplay.as_str(), "crash_replay");
        assert_eq!(WitnessSource::ValidateSkillPoc.as_str(), "validate_skill_poc");
        assert_eq!(WitnessSource::LlmEmitRun.as_str(), "llm_emit_run");
        assert_eq!(WitnessSource::Manual.as_str(), "manual");
    }

    #[test]
    fn test_witness_outcome_string_values_stable() {
        assert_eq!(WitnessOutcome::NotRun.as_str(), "not_run");
        assert_eq!(WitnessOutcome::NoObviousEffect.as_str(), "no_obvious_effect");
        assert_eq!(WitnessOutcome::ExitSignal.as_str(), "exit_signal");
        assert_eq!(WitnessOutcome::SanitizerReport.as_str(), "sanitizer_report");
        assert_eq!(WitnessOutcome::FlagCaptured.as_str(), "flag_captured");
        assert_eq!(WitnessOutcome::Unknown.as_str(), "unknown");
    }

    // -- Witness construction --

    #[test]
    fn test_witness_new_defaults() {
        let w = Witness::new(
            VALID_HASH.to_string(),
            WitnessSource::Fuzz,
            WitnessOutcome::ExitSignal,
        )
        .unwrap();
        assert_eq!(w.bytes_hash, VALID_HASH);
        assert_eq!(w.source, WitnessSource::Fuzz);
        assert_eq!(w.observed_outcome, WitnessOutcome::ExitSignal);
        assert_eq!(w.bytes_len, 0);
        assert!(w.target_binary_hash.is_none());
        assert!(w.target_source_hash.is_none());
        assert!(w.outcome_detail.is_empty());
        assert!(w.produced_by.is_none());
    }

    #[test]
    fn test_witness_rejects_truncated_hash() {
        let err = Witness::new(
            "a".repeat(32),
            WitnessSource::Fuzz,
            WitnessOutcome::ExitSignal,
        )
        .unwrap_err();
        assert!(err.0.contains("64-char"), "got: {}", err.0);
    }

    #[test]
    fn test_witness_rejects_non_hex_hash() {
        let err = Witness::new(
            "z".repeat(64),
            WitnessSource::Fuzz,
            WitnessOutcome::ExitSignal,
        )
        .unwrap_err();
        assert!(err.0.contains("hex"), "got: {}", err.0);
    }

    // -- to_dict / from_dict round-trip --

    #[test]
    fn test_to_dict_field_values() {
        // Python golden: Witness(bytes_hash=VALID_HASH, source=FUZZ,
        //   observed_outcome=EXIT_SIGNAL, bytes_len=42,
        //   produced_by="test-producer",
        //   timestamp=datetime(2026,1,15,12,30,45, tzinfo=timezone.utc)).to_dict()
        // → {"bytes_hash":"aaa...", "bytes_len":42, "source":"fuzz",
        //    "observed_outcome":"exit_signal", ...,
        //    "produced_by":"test-producer",
        //    "timestamp":"2026-01-15T12:30:45+00:00"}
        let ts = Utc.with_ymd_and_hms(2026, 1, 15, 12, 30, 45).unwrap();
        let mut w = Witness::new(
            VALID_HASH.to_string(),
            WitnessSource::Fuzz,
            WitnessOutcome::ExitSignal,
        )
        .unwrap();
        w.bytes_len = 42;
        w.produced_by = Some("test-producer".to_string());
        w.timestamp = ts;

        let d = w.to_dict();
        assert_eq!(d["bytes_hash"], Value::String(VALID_HASH.to_string()));
        assert_eq!(d["bytes_len"], Value::Number(42.into()));
        assert_eq!(d["source"], Value::String("fuzz".to_string()));
        assert_eq!(d["observed_outcome"], Value::String("exit_signal".to_string()));
        assert_eq!(d["target_binary_hash"], Value::Null);
        assert_eq!(d["target_source_hash"], Value::Null);
        assert_eq!(d["outcome_detail"], Value::Object(Map::new()));
        assert_eq!(d["produced_by"], Value::String("test-producer".to_string()));
        assert_eq!(d["timestamp"], Value::String("2026-01-15T12:30:45+00:00".to_string()));
    }

    #[test]
    fn test_from_dict_round_trip_minimal() {
        let mut w = Witness::new(
            VALID_HASH.to_string(),
            WitnessSource::Fuzz,
            WitnessOutcome::ExitSignal,
        )
        .unwrap();
        w.timestamp = Utc.with_ymd_and_hms(2026, 1, 15, 12, 30, 45).unwrap();

        let loaded = Witness::from_dict(&w.to_dict()).unwrap();
        assert_eq!(loaded.bytes_hash, w.bytes_hash);
        assert_eq!(loaded.source, w.source);
        assert_eq!(loaded.observed_outcome, w.observed_outcome);
    }

    #[test]
    fn test_from_dict_round_trip_full() {
        // Python golden: full Witness with all optional fields
        let ts = Utc.with_ymd_and_hms(2026, 1, 15, 12, 30, 45).unwrap();
        let mut w = Witness::new(
            VALID_HASH.to_string(),
            WitnessSource::CrashReplay,
            WitnessOutcome::SanitizerReport,
        )
        .unwrap();
        w.bytes_len = 256;
        w.target_binary_hash = Some("b".repeat(64));
        w.target_source_hash = Some("c".repeat(64));
        w.outcome_detail
            .insert("sanitizer".to_string(), Value::String("asan".to_string()));
        w.outcome_detail
            .insert("report".to_string(), Value::String("heap-buffer-overflow".to_string()));
        w.produced_by = Some("rr/replay".to_string());
        w.timestamp = ts;

        let loaded = Witness::from_dict(&w.to_dict()).unwrap();
        assert_eq!(loaded.bytes_hash, VALID_HASH);
        assert_eq!(loaded.source, WitnessSource::CrashReplay);
        assert_eq!(loaded.observed_outcome, WitnessOutcome::SanitizerReport);
        assert_eq!(loaded.bytes_len, 256);
        assert_eq!(loaded.target_binary_hash, Some("b".repeat(64)));
        assert_eq!(loaded.target_source_hash, Some("c".repeat(64)));
        assert_eq!(
            loaded.outcome_detail.get("sanitizer"),
            Some(&Value::String("asan".to_string()))
        );
        assert_eq!(loaded.produced_by, Some("rr/replay".to_string()));
        assert_eq!(loaded.timestamp, ts);
    }

    #[test]
    fn test_from_dict_ignores_extra_keys() {
        let data = serde_json::json!({
            "bytes_hash": VALID_HASH,
            "source": "fuzz",
            "observed_outcome": "exit_signal",
            "future_field_we_dont_know_about": "ignored",
            "another_one": {"nested": "thing"},
        });
        let w = Witness::from_dict(&data).unwrap();
        assert_eq!(w.bytes_hash, VALID_HASH);
    }

    #[test]
    fn test_from_dict_missing_optional_keys_default() {
        let data = serde_json::json!({
            "bytes_hash": VALID_HASH,
            "source": "fuzz",
            "observed_outcome": "exit_signal",
        });
        let w = Witness::from_dict(&data).unwrap();
        assert!(w.target_binary_hash.is_none());
        assert!(w.target_source_hash.is_none());
        assert!(w.outcome_detail.is_empty());
        assert!(w.produced_by.is_none());
        assert_eq!(w.bytes_len, 0);
    }

    #[test]
    fn test_from_dict_accepts_iso_timestamp() {
        // Python golden: "2026-01-15T12:30:45+00:00" → datetime(2026,1,15,12,30,45,tzinfo=UTC)
        let data = serde_json::json!({
            "bytes_hash": VALID_HASH,
            "source": "fuzz",
            "observed_outcome": "exit_signal",
            "timestamp": "2026-01-15T12:30:45+00:00",
        });
        let w = Witness::from_dict(&data).unwrap();
        let expected = Utc.with_ymd_and_hms(2026, 1, 15, 12, 30, 45).unwrap();
        assert_eq!(w.timestamp, expected);
    }

    #[test]
    fn test_from_dict_invalid_enum_raises() {
        let data = serde_json::json!({
            "bytes_hash": VALID_HASH,
            "source": "from_my_dreams",
            "observed_outcome": "exit_signal",
        });
        assert!(Witness::from_dict(&data).is_err());
    }
}
