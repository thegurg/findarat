//! Per-device chronological history.
//!
//! Observations and detected changes are merged into one newest-first stream so
//! a user can see what happened to a device without querying two tables.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashSet;

use crate::models::{Change, Device, Observation};

#[derive(Debug, Clone, Serialize)]
pub struct DeviceTimeline {
    pub device_id: Option<i64>,
    pub name: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub active: bool,
    pub ignored: bool,
    pub observation_count: usize,
    pub change_count: usize,
    pub sessions_seen: usize,
    pub events: Vec<TimelineEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventKind {
    Observation,
    Change,
}

impl TimelineEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Change => "change",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEvent {
    pub at: DateTime<Utc>,
    pub kind: TimelineEventKind,
    pub source: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

pub fn timeline(device: &Device, changes: &[Change], limit: Option<usize>) -> DeviceTimeline {
    let mut events = Vec::with_capacity(device.observations.len() + changes.len());
    for observation in &device.observations {
        events.push(observation_event(observation));
    }
    for change in changes {
        events.push(change_event(change));
    }
    events.sort_by(|left, right| {
        right
            .at
            .cmp(&left.at)
            .then_with(|| event_rank(right.kind).cmp(&event_rank(left.kind)))
    });
    if let Some(limit) = limit {
        events.truncate(limit);
    }

    let sessions_seen = device
        .observations
        .iter()
        .filter_map(|observation| observation.scan_id)
        .collect::<HashSet<_>>()
        .len();

    DeviceTimeline {
        device_id: device.id,
        name: device.display_name(),
        first_seen: device.first_seen,
        last_seen: device.last_seen,
        active: device.active,
        ignored: device.ignored,
        observation_count: device.observations.len(),
        change_count: changes.len(),
        sessions_seen,
        events,
    }
}

fn event_rank(kind: TimelineEventKind) -> u8 {
    match kind {
        TimelineEventKind::Change => 1,
        TimelineEventKind::Observation => 0,
    }
}

fn observation_event(observation: &Observation) -> TimelineEvent {
    let mut parts = Vec::new();
    if let Some(ip) = observation.ip {
        parts.push(ip.to_string());
    }
    if let Some(mac) = &observation.mac {
        parts.push(mac.clone());
    }
    if let Some(hostname) = &observation.hostname {
        parts.push(hostname.clone());
    }
    let summary = if parts.is_empty() {
        "observed".to_string()
    } else {
        parts.join(" · ")
    };
    TimelineEvent {
        at: observation.observed_at,
        kind: TimelineEventKind::Observation,
        source: observation.source.clone(),
        summary,
        details: observation.details.clone(),
    }
}

fn change_event(change: &Change) -> TimelineEvent {
    let summary = match (&change.old_value, &change.new_value) {
        (Some(old), Some(new)) => format!("{old} → {new}"),
        (None, Some(new)) => new.clone(),
        (Some(old), None) => format!("{old} → —"),
        (None, None) => "changed".to_string(),
    };
    TimelineEvent {
        at: change.detected_at,
        kind: TimelineEventKind::Change,
        source: change.kind.label().to_string(),
        summary,
        details: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ChangeKind, Observation};

    #[test]
    fn merges_and_sorts_events_newest_first() {
        let now = Utc::now();
        let mut device = Device::new(now - chrono::Duration::hours(2), now);
        device.id = Some(1);
        device.hostname = Some("alpha".to_string());
        let mut older = Observation::new(now - chrono::Duration::hours(1), "arp");
        older.ip = Some("192.168.1.10".parse().unwrap());
        older.scan_id = Some(3);
        let mut newer = Observation::new(now, "mdns");
        newer.hostname = Some("alpha".to_string());
        newer.scan_id = Some(4);
        device.observations = vec![older, newer];

        let change = Change {
            id: Some(1),
            scan_id: Some(4),
            device_id: 1,
            kind: ChangeKind::IpChanged,
            old_value: Some("192.168.1.10".to_string()),
            new_value: Some("192.168.1.11".to_string()),
            detected_at: now + chrono::Duration::minutes(1),
            device_label: Some("alpha".to_string()),
        };

        let timeline = timeline(&device, &[change], None);
        assert_eq!(timeline.observation_count, 2);
        assert_eq!(timeline.change_count, 1);
        assert_eq!(timeline.sessions_seen, 2);
        assert_eq!(timeline.events.len(), 3);
        assert_eq!(timeline.events[0].kind, TimelineEventKind::Change);
        assert_eq!(timeline.events[1].kind, TimelineEventKind::Observation);
        assert!(timeline.events[1].summary.contains("alpha"));
    }

    #[test]
    fn limit_truncates_events_without_changing_counts() {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        device.observations = (0..5)
            .map(|index| Observation::new(now - chrono::Duration::minutes(index), "arp"))
            .collect();
        let timeline = timeline(&device, &[], Some(2));
        assert_eq!(timeline.events.len(), 2);
        assert_eq!(timeline.observation_count, 5);
    }
}
