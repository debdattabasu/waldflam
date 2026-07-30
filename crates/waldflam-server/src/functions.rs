//! Cloud Functions triggers: Firestore document events delivered to user
//! code over HTTP.
//!
//! Triggers subscribe to the same commit hub that powers Listen, so a write
//! through any surface (gRPC, REST, WebChannel, the Write stream) fires them.
//! Events are CloudEvents 1.0 in structured mode, with Firestore's document
//! payloads in proto3-JSON — the format 2nd-gen Firestore functions receive:
//!
//! ```json
//! {"specversion":"1.0",
//!  "type":"google.cloud.firestore.document.v1.created",
//!  "source":"//firestore.googleapis.com/projects/p/databases/(default)",
//!  "subject":"documents/users/alice",
//!  "id":"...", "time":"...",
//!  "data":{"oldValue":{...},"value":{...},"updateMask":{...}},
//!  "params":{"userId":"alice"}}
//! ```

use std::sync::{Arc, RwLock};

use prost_reflect::DescriptorPool;
use serde::{Deserialize, Serialize};
use waldflam_engine::path::{DatabaseName, ResourcePath};
use waldflam_engine::store::StoredDocument;
use waldflam_engine::watch::{DocumentDelta, WatchHub};
use waldflam_proto::v1::Document;

const MAX_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Created,
    Updated,
    Deleted,
    /// Any of the above.
    Written,
}

impl EventKind {
    fn type_name(self) -> &'static str {
        match self {
            EventKind::Created => "google.cloud.firestore.document.v1.created",
            EventKind::Updated => "google.cloud.firestore.document.v1.updated",
            EventKind::Deleted => "google.cloud.firestore.document.v1.deleted",
            EventKind::Written => "google.cloud.firestore.document.v1.written",
        }
    }

    fn actual(delta: &DocumentDelta) -> Self {
        match (&delta.before, &delta.after) {
            (None, Some(_)) => EventKind::Created,
            (Some(_), Some(_)) => EventKind::Updated,
            _ => EventKind::Deleted,
        }
    }

    fn covers(self, actual: Self) -> bool {
        self == EventKind::Written || self == actual
    }
}

#[derive(Debug, Deserialize)]
pub struct TriggerSpec {
    pub id: String,
    /// Document path pattern, e.g. `users/{userId}` or `chats/{c}/msgs/{m}`.
    /// A `{name=**}` segment matches one or more trailing segments.
    pub pattern: String,
    pub event: EventKind,
    /// HTTP endpoint receiving the CloudEvent.
    pub endpoint: String,
}

#[derive(Debug, Clone)]
struct Trigger {
    id: String,
    segments: Vec<PatternSeg>,
    event: EventKind,
    endpoint: String,
}

#[derive(Debug, Clone)]
enum PatternSeg {
    Literal(String),
    Capture(String),
    Glob(String),
}

fn parse_pattern(pattern: &str) -> Vec<PatternSeg> {
    pattern
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some(inner) => match inner.strip_suffix("=**") {
                Some(name) => PatternSeg::Glob(name.to_owned()),
                None => PatternSeg::Capture(inner.to_owned()),
            },
            None => PatternSeg::Literal(seg.to_owned()),
        })
        .collect()
}

/// Matches a document path against a pattern, returning captured params.
fn match_pattern(segments: &[PatternSeg], path: &ResourcePath) -> Option<Vec<(String, String)>> {
    let parts = path.segments();
    let mut params = Vec::new();
    let mut i = 0;
    for (si, seg) in segments.iter().enumerate() {
        match seg {
            PatternSeg::Literal(lit) => {
                if parts.get(i)? != lit {
                    return None;
                }
                i += 1;
            }
            PatternSeg::Capture(name) => {
                params.push((name.clone(), parts.get(i)?.clone()));
                i += 1;
            }
            PatternSeg::Glob(name) => {
                let trailing = segments.len() - si - 1;
                if parts.len() < i + trailing + 1 {
                    return None; // globs need at least one segment
                }
                let take = parts.len() - trailing - i;
                params.push((name.clone(), parts[i..i + take].join("/")));
                i += take;
            }
        }
    }
    (i == parts.len()).then_some(params)
}

#[derive(Default)]
pub struct TriggerRegistry {
    triggers: RwLock<Vec<Trigger>>,
}

impl TriggerRegistry {
    pub fn replace(&self, specs: Vec<TriggerSpec>) {
        let triggers = specs
            .into_iter()
            .map(|spec| Trigger {
                id: spec.id,
                segments: parse_pattern(&spec.pattern),
                event: spec.event,
                endpoint: spec.endpoint,
            })
            .collect();
        *self.triggers.write().expect("triggers lock") = triggers;
    }

    pub fn len(&self) -> usize {
        self.triggers.read().expect("triggers lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn snapshot(&self) -> Vec<Trigger> {
        self.triggers.read().expect("triggers lock").clone()
    }
}

/// Subscribes to commits and dispatches matching trigger events.
pub fn spawn_dispatcher(hub: Arc<WatchHub>, registry: Arc<TriggerRegistry>, pool: DescriptorPool) {
    tokio::spawn(async move {
        let mut events = hub.subscribe();
        let client = reqwest::Client::new();
        loop {
            let event = match events.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(dropped = n, "trigger dispatcher lagged");
                    continue;
                }
                Err(_) => return,
            };
            if registry.is_empty() {
                continue;
            }
            for trigger in registry.snapshot() {
                for delta in &event.changes {
                    let actual = EventKind::actual(delta);
                    if !trigger.event.covers(actual) {
                        continue;
                    }
                    let Some(params) = match_pattern(&trigger.segments, &delta.path) else {
                        continue;
                    };
                    let payload = cloud_event(
                        &pool,
                        &trigger,
                        actual,
                        &event.database,
                        delta,
                        event.commit_us,
                        params,
                    );
                    let client = client.clone();
                    let endpoint = trigger.endpoint.clone();
                    let id = trigger.id.clone();
                    tokio::spawn(async move {
                        deliver(&client, &endpoint, &id, payload).await;
                    });
                }
            }
        }
    });
}

async fn deliver(
    client: &reqwest::Client,
    endpoint: &str,
    trigger_id: &str,
    payload: serde_json::Value,
) {
    for attempt in 1..=MAX_ATTEMPTS {
        let result = client
            .post(endpoint)
            .header("content-type", "application/cloudevents+json")
            .json(&payload)
            .send()
            .await;
        match result {
            Ok(response) if response.status().is_success() => return,
            Ok(response) => {
                tracing::warn!(
                    trigger = trigger_id,
                    status = %response.status(),
                    attempt,
                    "trigger delivery failed"
                );
            }
            Err(e) => {
                tracing::warn!(trigger = trigger_id, error = %e, attempt, "trigger delivery error");
            }
        }
        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(std::time::Duration::from_millis(100 * attempt as u64)).await;
        }
    }
}

fn cloud_event(
    pool: &DescriptorPool,
    trigger: &Trigger,
    actual: EventKind,
    database: &DatabaseName,
    delta: &DocumentDelta,
    commit_us: i64,
    params: Vec<(String, String)>,
) -> serde_json::Value {
    let name = format!("{}/{}", database.documents_root(), delta.path);
    let to_json = |doc: Option<&StoredDocument>| match doc {
        Some(doc) => document_json(pool, &name, doc),
        None => serde_json::json!({}),
    };
    let time = chrono_rfc3339(commit_us);
    serde_json::json!({
        "specversion": "1.0",
        "type": actual.type_name(),
        "source": format!("//firestore.googleapis.com/{database}"),
        "subject": format!("documents/{}", delta.path),
        "id": format!("{}-{}-{}", trigger.id, delta.path, commit_us),
        "time": time,
        "datacontenttype": "application/json",
        "params": params
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect::<serde_json::Map<String, serde_json::Value>>(),
        "data": {
            "oldValue": to_json(delta.before.as_ref()),
            "value": to_json(delta.after.as_ref()),
        },
    })
}

fn document_json(pool: &DescriptorPool, name: &str, doc: &StoredDocument) -> serde_json::Value {
    let wire = Document {
        name: name.to_owned(),
        fields: doc.fields.clone(),
        create_time: Some(crate::service::timestamp_from_us(doc.create_time_us)),
        update_time: Some(crate::service::timestamp_from_us(doc.update_time_us)),
    };
    let descriptor =
        pool.get_message_by_name("google.firestore.v1.Document").expect("Document descriptor");
    use prost::Message as _;
    let bytes = wire.encode_to_vec();
    let dynamic = prost_reflect::DynamicMessage::decode(descriptor, bytes.as_slice())
        .expect("encode document");
    serde_json::to_value(&dynamic).unwrap_or(serde_json::Value::Null)
}

/// RFC-3339 UTC timestamp from microseconds since the epoch.
fn chrono_rfc3339(us: i64) -> String {
    let secs = us.div_euclid(1_000_000);
    let micros = us.rem_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        sod / 3600,
        (sod / 60) % 60,
        sod % 60
    )
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(p: &str) -> ResourcePath {
        ResourcePath::parse(p).unwrap()
    }

    #[test]
    fn patterns_match_and_capture() {
        let p = parse_pattern("users/{userId}");
        assert_eq!(
            match_pattern(&p, &path("users/alice")),
            Some(vec![("userId".into(), "alice".into())])
        );
        // Wrong depth doesn't match.
        assert_eq!(match_pattern(&p, &path("users/alice/posts/p1")), None);
        assert_eq!(match_pattern(&p, &path("teams/alice")), None);

        let nested = parse_pattern("chats/{chatId}/messages/{msgId}");
        assert_eq!(
            match_pattern(&nested, &path("chats/c1/messages/m1")),
            Some(vec![("chatId".into(), "c1".into()), ("msgId".into(), "m1".into())])
        );

        let glob = parse_pattern("data/{rest=**}");
        assert_eq!(
            match_pattern(&glob, &path("data/a/b/c")),
            Some(vec![("rest".into(), "a/b/c".into())])
        );
        assert_eq!(match_pattern(&glob, &path("data")), None, "glob needs a segment");
    }

    #[test]
    fn event_kind_from_transition() {
        let doc = |us: i64| StoredDocument {
            path: path("c/d"),
            create_time_us: us,
            update_time_us: us,
            fields: Default::default(),
        };
        let delta = |before, after| DocumentDelta { path: path("c/d"), before, after };
        assert_eq!(EventKind::actual(&delta(None, Some(doc(1)))), EventKind::Created);
        assert_eq!(EventKind::actual(&delta(Some(doc(1)), Some(doc(2)))), EventKind::Updated);
        assert_eq!(EventKind::actual(&delta(Some(doc(1)), None)), EventKind::Deleted);
        // `written` covers everything; specific kinds don't cross-match.
        assert!(EventKind::Written.covers(EventKind::Created));
        assert!(EventKind::Written.covers(EventKind::Deleted));
        assert!(EventKind::Created.covers(EventKind::Created));
        assert!(!EventKind::Created.covers(EventKind::Updated));
    }

    #[test]
    fn rfc3339_formatting() {
        assert_eq!(chrono_rfc3339(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(chrono_rfc3339(1_000_000), "1970-01-01T00:00:01.000000Z");
        // Cross-checked against an independent date implementation.
        assert_eq!(chrono_rfc3339(1_785_000_000_000_000), "2026-07-25T17:20:00.000000Z");
        assert_eq!(chrono_rfc3339(1_785_000_000_123_456), "2026-07-25T17:20:00.123456Z");
    }
}
