//! Evidence and confidence primitives.
//!
//! Every inferred property in findarat is paired with an [`Evidence`] record.
//! Direct observations and inferences are deliberately distinct: a MAC address
//! read from the kernel neighbour table is a direct observation, while a vendor
//! name looked up in the OUI database is a database inference.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Quality of the evidence behind a property. This is intentionally not a
/// numeric score: it describes *why* a value is believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Directly observed, or produced by an authoritative local source.
    High,
    /// A strong inference or a stable database match.
    Medium,
    /// A weak heuristic, or an ambiguous match.
    Low,
    /// The value exists but its reliability is not established.
    #[default]
    Unknown,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }

    /// Rank used for sorting and for "highest confidence wins" presentation.
    /// Higher is stronger. Unknown is deliberately below Low.
    pub fn rank(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Confidence {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "unknown" => Ok(Self::Unknown),
            other => Err(format!("invalid confidence level: {other}")),
        }
    }
}

/// How a value came to be known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Observed directly (ARP table, DNS response, TCP banner, ...).
    DirectObservation,
    /// Inferred by looking a value up in a local database (OUI, port table).
    DatabaseInference,
    /// Inferred probabilistically from behaviour or patterns.
    #[default]
    ProbabilisticInference,
    /// Entered by the user (for example an import or a manual label).
    UserProvided,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectObservation => "direct_observation",
            Self::DatabaseInference => "database_inference",
            Self::ProbabilisticInference => "probabilistic_inference",
            Self::UserProvided => "user_provided",
        }
    }
}

impl fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EvidenceKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "direct_observation" | "direct" => Ok(Self::DirectObservation),
            "database_inference" | "database" => Ok(Self::DatabaseInference),
            "probabilistic_inference" | "probabilistic" => Ok(Self::ProbabilisticInference),
            "user_provided" | "user" => Ok(Self::UserProvided),
            other => Err(format!("invalid evidence kind: {other}")),
        }
    }
}

/// A single, attributable piece of support for a device property.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// Property name, e.g. `mac`, `vendor`, `operating_system`, `device_type`.
    pub property: String,
    /// Observed or inferred value.
    pub value: String,
    /// Provider or subsystem that produced the record.
    pub source: String,
    pub confidence: Confidence,
    pub kind: EvidenceKind,
    pub observed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Evidence {
    pub fn new(
        property: impl Into<String>,
        value: impl Into<String>,
        source: impl Into<String>,
        confidence: Confidence,
        kind: EvidenceKind,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: None,
            property: property.into(),
            value: value.into(),
            source: source.into(),
            confidence,
            kind,
            observed_at,
            note: None,
        }
    }

    pub fn direct(
        property: impl Into<String>,
        value: impl Into<String>,
        source: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self::new(
            property,
            value,
            source,
            Confidence::High,
            EvidenceKind::DirectObservation,
            observed_at,
        )
    }

    pub fn inferred(
        property: impl Into<String>,
        value: impl Into<String>,
        source: impl Into<String>,
        confidence: Confidence,
        kind: EvidenceKind,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self::new(property, value, source, confidence, kind, observed_at)
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_ordering() {
        assert!(Confidence::High.rank() > Confidence::Medium.rank());
        assert!(Confidence::Medium.rank() > Confidence::Low.rank());
        assert!(Confidence::Low.rank() > Confidence::Unknown.rank());
    }

    #[test]
    fn confidence_round_trips_through_strings() {
        for level in [
            Confidence::High,
            Confidence::Medium,
            Confidence::Low,
            Confidence::Unknown,
        ] {
            assert_eq!(level.as_str().parse::<Confidence>().unwrap(), level);
        }
        assert!("certain".parse::<Confidence>().is_err());
    }

    #[test]
    fn evidence_serializes_with_snake_case_enums() {
        let evidence = Evidence::direct("mac", "AA:BB:CC:DD:EE:FF", "arp", Utc::now());
        let json = serde_json::to_string(&evidence).unwrap();
        assert!(json.contains("\"confidence\":\"high\""));
        assert!(json.contains("\"kind\":\"direct_observation\""));
    }
}
