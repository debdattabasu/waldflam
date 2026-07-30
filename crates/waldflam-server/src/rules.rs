//! Firestore binding for the rules engine: converts documents and requests
//! into rules values, evaluates access, and enforces the outcome.
//!
//! Policy (docs/architecture.md §3/§7): `Bearer owner` bypasses rules
//! entirely (admin/server SDKs); unauthenticated and user traffic is
//! evaluated. Missing ruleset ⇒ open (what the emulator does when no rules
//! file is configured).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use tonic::Status;
use waldflam_engine::path::{DatabaseName, ResourcePath};
use waldflam_engine::store::{Store, StoredDocument};
use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::{Document, Value as PValue};
use waldflam_rules::value::Value;
use waldflam_rules::{Decision, Operation, Ruleset};

use crate::auth::Authorization;

/// Per-database rulesets, hot-swappable via the admin API.
#[derive(Default)]
pub struct RulesRegistry {
    inner: RwLock<BTreeMap<String, Arc<Ruleset>>>,
}

impl RulesRegistry {
    pub fn set(&self, database: &DatabaseName, ruleset: Ruleset) {
        self.inner.write().expect("rules lock").insert(database.to_string(), Arc::new(ruleset));
    }

    pub fn get(&self, database: &DatabaseName) -> Option<Arc<Ruleset>> {
        self.inner.read().expect("rules lock").get(&database.to_string()).cloned()
    }

    pub fn clear(&self, database: &DatabaseName) {
        self.inner.write().expect("rules lock").remove(&database.to_string());
    }
}

/// Rules `Host`: serves `get()`/`exists()` from the store, with a
/// per-evaluation cache so repeated lookups cost one round trip.
struct StoreHost<'a> {
    store: &'a Store,
    database: &'a DatabaseName,
    handle: tokio::runtime::Handle,
    cache: BTreeMap<String, Option<Value>>,
}

impl<'a> StoreHost<'a> {
    fn lookup(&mut self, path: &[String]) -> Result<Option<Value>, String> {
        // Rules paths are `databases/{db}/documents/...`; strip the prefix.
        let relative = match path.first().map(String::as_str) {
            Some("databases") => path.get(3..).unwrap_or_default(),
            _ => path,
        };
        let key = relative.join("/");
        if let Some(hit) = self.cache.get(&key) {
            return Ok(hit.clone());
        }
        let parsed = ResourcePath::parse(&key).map_err(|e| e.to_string())?;
        if !parsed.is_document() {
            return Err("not a document path".into());
        }
        // The engine is synchronous; block on the store from a blocking
        // context (rules evaluation runs inside spawn_blocking).
        let found = tokio::task::block_in_place(|| {
            self.handle.block_on(self.store.get_document(self.database, &parsed))
        })
        .map_err(|e| e.to_string())?;
        let value = found.map(|doc| document_value(&doc));
        self.cache.insert(key, value.clone());
        Ok(value)
    }
}

impl waldflam_rules::Host for StoreHost<'_> {
    fn get_document(&mut self, path: &[String], _after: bool) -> Result<Option<Value>, String> {
        self.lookup(path)
    }

    fn exists(&mut self, path: &[String], _after: bool) -> Result<bool, String> {
        Ok(self.lookup(path)?.is_some())
    }
}

/// `resource` shape: `{data: {...}, id: <docId>, __name__: <path>}`.
fn document_value(doc: &StoredDocument) -> Value {
    let mut map = BTreeMap::new();
    map.insert("data".into(), fields_value(&doc.fields));
    if let Some(id) = doc.path.last_id() {
        map.insert("id".into(), Value::str(id));
    }
    map.insert("__name__".into(), Value::Path(Arc::new(doc.path.segments().to_vec())));
    Value::map(map)
}

fn fields_value(fields: &std::collections::HashMap<String, PValue>) -> Value {
    let mut out = BTreeMap::new();
    for (k, v) in fields {
        out.insert(k.clone(), proto_value(v));
    }
    Value::map(out)
}

fn proto_value(value: &PValue) -> Value {
    match value.value_type.as_ref() {
        None | Some(ValueType::NullValue(_)) => Value::Null,
        Some(ValueType::BooleanValue(b)) => Value::Bool(*b),
        Some(ValueType::IntegerValue(i)) => Value::Int(*i),
        Some(ValueType::DoubleValue(d)) => Value::Float(*d),
        Some(ValueType::StringValue(s)) => Value::str(s.as_str()),
        Some(ValueType::BytesValue(b)) => Value::Bytes(Arc::from(b.as_ref())),
        Some(ValueType::TimestampValue(ts)) => Value::Timestamp(ts.seconds, ts.nanos as u32),
        Some(ValueType::GeoPointValue(g)) => Value::LatLng(g.latitude, g.longitude),
        Some(ValueType::ReferenceValue(r)) => {
            Value::Path(Arc::new(r.split('/').map(str::to_owned).collect()))
        }
        Some(ValueType::ArrayValue(a)) => Value::list(a.values.iter().map(proto_value).collect()),
        Some(ValueType::MapValue(m)) => {
            let mut out = BTreeMap::new();
            for (k, v) in &m.fields {
                out.insert(k.clone(), proto_value(v));
            }
            Value::map(out)
        }
        // Pipeline expression values never appear in stored documents.
        Some(_) => Value::Null,
    }
}

/// One access check.
pub struct AccessRequest<'a> {
    pub database: &'a DatabaseName,
    pub path: &'a ResourcePath,
    pub operation: Operation,
    /// Post-write document state (create/update) for `request.resource`.
    pub incoming: Option<&'a Document>,
    /// Pre-existing document for `resource`.
    pub existing: Option<&'a StoredDocument>,
}

/// Evaluates rules for one access; `Ok(())` means allowed.
pub async fn check(
    registry: &RulesRegistry,
    store: &Store,
    auth: &Authorization,
    request: AccessRequest<'_>,
) -> Result<(), Status> {
    // Admin bypasses rules entirely.
    if matches!(auth, Authorization::Admin) {
        return Ok(());
    }
    let Some(ruleset) = registry.get(request.database) else {
        return Ok(()); // no rules configured ⇒ open, like the emulator
    };

    // request.auth
    let auth_value = match auth {
        Authorization::User(claims) => {
            let mut map = BTreeMap::new();
            map.insert("uid".into(), claims.uid.as_deref().map(Value::str).unwrap_or(Value::Null));
            let mut token = BTreeMap::new();
            for (k, v) in &claims.payload {
                token.insert(k.clone(), json_value(v));
            }
            map.insert("token".into(), Value::map(token));
            Value::map(map)
        }
        _ => Value::Null,
    };

    let now = crate::service::now_us();
    let mut request_map = BTreeMap::new();
    request_map.insert("auth".into(), auth_value);
    request_map.insert(
        "time".into(),
        Value::Timestamp(now.div_euclid(1_000_000), (now.rem_euclid(1_000_000) * 1_000) as u32),
    );
    request_map.insert("method".into(), Value::str(request.operation.id()));
    // Full rules path: databases/{db}/documents/<doc path>
    let mut rules_path = vec![
        "databases".to_string(),
        request.database.database_id.clone(),
        "documents".to_string(),
    ];
    rules_path.extend(request.path.segments().iter().cloned());
    if request.operation == Operation::List {
        // Queries authorize against "any document in this collection".
        rules_path.push(waldflam_rules::WILDCARD_SEGMENT.to_string());
    }
    request_map.insert("path".into(), Value::Path(Arc::new(rules_path.clone())));
    if let Some(incoming) = request.incoming {
        let mut res = BTreeMap::new();
        res.insert("data".into(), fields_value(&incoming.fields));
        if let Some(id) = request.path.last_id() {
            res.insert("id".into(), Value::str(id));
        }
        request_map.insert("resource".into(), Value::map(res));
    }

    let resource_value = match request.existing {
        Some(doc) => document_value(doc),
        None => Value::Null,
    };

    let globals = vec![
        ("request".to_string(), Value::map(request_map)),
        ("resource".to_string(), resource_value),
    ];

    let mut host = StoreHost {
        store,
        database: request.database,
        handle: tokio::runtime::Handle::current(),
        cache: BTreeMap::new(),
    };
    let decision = waldflam_rules::evaluate(
        &ruleset,
        "cloud.firestore",
        request.operation,
        &rules_path,
        &globals,
        &mut host,
    )
    .map_err(|fatal| Status::permission_denied(fatal.0))?;

    match decision {
        Decision::Allow => Ok(()),
        Decision::Deny => Err(Status::permission_denied("Missing or insufficient permissions.")),
    }
}

/// Rules enforcement for a batch of writes (Commit and the Write stream
/// share this). Determines create-vs-update from current existence.
pub async fn check_writes(
    registry: &RulesRegistry,
    store: &Store,
    auth: &Authorization,
    database: &DatabaseName,
    writes: &[waldflam_proto::v1::Write],
) -> Result<(), Status> {
    use waldflam_proto::v1::write::Operation as WriteOp;
    if matches!(auth, Authorization::Admin) {
        return Ok(());
    }
    if registry.get(database).is_none() {
        return Ok(());
    }
    for write in writes {
        let (name, incoming, hint) = match write.operation.as_ref() {
            Some(WriteOp::Update(doc)) => (doc.name.clone(), Some(doc), None),
            Some(WriteOp::Delete(name)) => (name.clone(), None, Some(Operation::Delete)),
            Some(WriteOp::Transform(t)) => (t.document.clone(), None, None),
            Some(WriteOp::Verify(name)) => (name.clone(), None, Some(Operation::Get)),
            None => continue,
        };
        let parsed = waldflam_engine::path::ResourceName::parse_document(&name)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let existing = store
            .get_document(database, &parsed.path)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let operation =
            hint.unwrap_or(if existing.is_some() { Operation::Update } else { Operation::Create });
        check(
            registry,
            store,
            auth,
            AccessRequest {
                database,
                path: &parsed.path,
                operation,
                incoming,
                existing: existing.as_ref(),
            },
        )
        .await?;
    }
    Ok(())
}

fn json_value(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i),
            None => Value::Float(n.as_f64().unwrap_or(f64::NAN)),
        },
        serde_json::Value::String(s) => Value::str(s.as_str()),
        serde_json::Value::Array(items) => Value::list(items.iter().map(json_value).collect()),
        serde_json::Value::Object(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                out.insert(k.clone(), json_value(v));
            }
            Value::map(out)
        }
    }
}
