//! SCA dependency model — Rust port of the `Dependency` / `PinStyle` /
//! `Confidence` core of `packages/sca/models.py`. The richer finding/advisory
//! models are ported as their consumers are.

use serde_json::{json, Value};

/// How tightly a manifest declares a version (`PinStyle`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinStyle {
    Exact,
    Caret,
    Tilde,
    Range,
    Wildcard,
    Git,
    Path,
    Unknown,
}

impl PinStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            PinStyle::Exact => "exact",
            PinStyle::Caret => "caret",
            PinStyle::Tilde => "tilde",
            PinStyle::Range => "range",
            PinStyle::Wildcard => "wildcard",
            PinStyle::Git => "git",
            PinStyle::Path => "path",
            PinStyle::Unknown => "unknown",
        }
    }
}

/// Cross-cutting confidence for a signal (`Confidence`). The standard
/// level->numeric mapping is applied unless an explicit numeric is given;
/// `reason` is truncated to 200 chars (197 + "...").
#[derive(Clone, Debug, PartialEq)]
pub struct Confidence {
    pub level: String,
    pub reason: String,
    pub numeric: f64,
}

impl Confidence {
    pub fn new(level: &str, reason: &str) -> Self {
        let numeric = match level {
            "low" => 0.30,
            "medium" => 0.70,
            "high" => 0.95,
            _ => 0.30,
        };
        let reason = if reason.chars().count() > 200 {
            let truncated: String = reason.chars().take(197).collect();
            format!("{truncated}...")
        } else {
            reason.to_string()
        };
        Self { level: level.to_string(), reason, numeric }
    }

    pub fn to_json(&self) -> Value {
        json!({"level": self.level, "reason": self.reason, "numeric": self.numeric})
    }
}

/// A single dep observed in a manifest or lockfile (`Dependency`). Only the
/// fields the parsers populate are modelled; defaults match the dataclass.
#[derive(Clone, Debug, PartialEq)]
pub struct Dependency {
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub declared_in: String,
    pub scope: String,
    pub is_lockfile: bool,
    pub pin_style: PinStyle,
    pub direct: bool,
    pub purl: String,
    pub parser_confidence: Confidence,
    pub declared_license: Option<String>,
    pub commented_out: bool,
    pub source_kind: String,
}

impl Dependency {
    /// Stable identity for dedup (`key`): `ecosystem:name@version-or-*`.
    pub fn key(&self) -> String {
        format!("{}:{}@{}", self.ecosystem, self.name, self.version.as_deref().unwrap_or("*"))
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "declared_in": self.declared_in,
            "scope": self.scope,
            "is_lockfile": self.is_lockfile,
            "pin_style": self.pin_style.as_str(),
            "direct": self.direct,
            "purl": self.purl,
            "parser_confidence": self.parser_confidence.to_json(),
            "declared_license": self.declared_license,
            "commented_out": self.commented_out,
            "source_kind": self.source_kind,
            "key": self.key(),
        })
    }
}
