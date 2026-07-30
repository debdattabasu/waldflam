//! MongoDB-backed document storage.
//!
//! One flat Mongo collection per Firestore database (named
//! `{project}~{database}`), one row per document:
//!
//! - `_id`: the relative document path (`users/alice/posts/p1`)
//! - `collection_path` / `collection_id`: for collection and
//!   collection-group targeting
//! - `create_time_us` / `update_time_us`: microsecond timestamps —
//!   `update_time_us` is also the document version for preconditions
//! - `payload`: the full field map as a prost-encoded `Document` (lossless)
//! - `indexed`: derived index entries in the attribute pattern —
//!   `{p: <dotted field path>, k: "v"|"e", v: <hex index key>}`. Kind `"v"`
//!   is the field's whole value (equality/range/order-by); `"e"` is one
//!   entry per array element (`array-contains`). `__name__` is always
//!   present, so every document has at least one entry.

use std::collections::HashMap;
use std::sync::Arc;

use mongodb::bson::spec::BinarySubtype;
use mongodb::bson::{Binary, doc, to_bson};
use mongodb::options::ReturnDocument;
use mongodb::{Client, ClientSession, Collection, Database};
use prost::Message;
use serde::{Deserialize, Serialize};
use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::{Document, Value};

use crate::EngineError;
use crate::index_key::{encode_value, to_index_string};
use crate::path::{DatabaseName, ResourcePath};

/// Read-side row shape; `indexed` is write-only (set via the update
/// document, queried server-side, never read back).
#[derive(Debug, Deserialize)]
struct DocRow {
    #[serde(rename = "_id")]
    id: String,
    #[allow(dead_code)]
    collection_path: String,
    #[allow(dead_code)]
    collection_id: String,
    create_time_us: i64,
    update_time_us: i64,
    payload: Binary,
}

#[derive(Debug, Serialize)]
struct IndexEntry {
    p: String,
    k: &'static str,
    v: String,
}

/// A document as read back from storage.
#[derive(Debug, Clone)]
pub struct StoredDocument {
    pub path: ResourcePath,
    pub create_time_us: i64,
    pub update_time_us: i64,
    pub fields: HashMap<String, Value>,
}

/// Name of the shared collection every instance writes commit notices to and
/// tails for other instances' commits.
const EVENTS: &str = "_commit_events";

/// How long a commit notice lives before MongoDB's TTL monitor reaps it.
/// Only needs to outlast the moment a tailing instance reads it.
const EVENT_TTL_SECONDS: u64 = 3600;

/// A commit notice: which paths a commit touched, and who applied it.
/// Deliberately payload-free — it stays small no matter how large the
/// documents were, and readers fetch whatever state they actually need.
#[derive(Debug, Serialize, Deserialize)]
pub struct CommitNotice {
    pub instance: String,
    pub project_id: String,
    pub database_id: String,
    pub commit_us: i64,
    pub paths: Vec<String>,
    /// TTL anchor; MongoDB reaps the notice once this passes.
    pub expires_at: mongodb::bson::DateTime,
}

#[derive(Clone)]
pub struct Store {
    db: Database,
    /// Identifies this process's commits so the fan-out tail can skip the
    /// ones it published itself (already delivered in-process).
    instance_id: Arc<str>,
}

impl Store {
    pub async fn connect(uri: &str) -> Result<Self, EngineError> {
        let client = Client::with_uri_str(uri).await?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or(0);
        let store = Self {
            db: client.database("waldflam"),
            instance_id: format!("{}-{nanos}", std::process::id()).into(),
        };
        store.ensure_event_ttl_index().await?;
        Ok(store)
    }

    /// This process's identity in the shared event collection.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    fn events(&self) -> Collection<CommitNotice> {
        self.db.collection(EVENTS)
    }

    /// Lets MongoDB reap old commit notices instead of growing forever.
    /// Creating an index that already exists is a no-op.
    async fn ensure_event_ttl_index(&self) -> Result<(), EngineError> {
        let index = mongodb::IndexModel::builder()
            .keys(doc! { "expires_at": 1 })
            .options(
                mongodb::options::IndexOptions::builder()
                    .expire_after(std::time::Duration::from_secs(0))
                    .build(),
            )
            .build();
        self.events().create_index(index).await?;
        Ok(())
    }

    /// Records what a commit touched, inside that commit's transaction — so
    /// the notice becomes visible exactly when the writes do, and is rolled
    /// back with them if the commit fails.
    pub async fn append_commit_notice_in_session(
        &self,
        session: &mut ClientSession,
        database: &DatabaseName,
        commit_us: i64,
        paths: Vec<String>,
    ) -> Result<(), EngineError> {
        let expires_at = mongodb::bson::DateTime::from_system_time(
            std::time::SystemTime::now() + std::time::Duration::from_secs(EVENT_TTL_SECONDS),
        );
        let notice = CommitNotice {
            instance: self.instance_id.to_string(),
            project_id: database.project_id.clone(),
            database_id: database.database_id.clone(),
            commit_us,
            paths,
            expires_at,
        };
        let events = self.events();
        events.insert_one(notice).session(session).await?;
        Ok(())
    }

    /// Tails commit notices from every instance. `resume_after` continues an
    /// earlier stream so a reconnect doesn't skip commits.
    pub async fn watch_commit_notices(
        &self,
        resume_after: Option<mongodb::change_stream::event::ResumeToken>,
    ) -> Result<
        mongodb::change_stream::ChangeStream<
            mongodb::change_stream::event::ChangeStreamEvent<CommitNotice>,
        >,
        EngineError,
    > {
        let events = self.events();
        let watch = events.watch();
        let watch = match resume_after {
            Some(token) => watch.resume_after(token),
            None => watch,
        };
        Ok(watch.await?)
    }

    fn collection(&self, database: &DatabaseName) -> Collection<DocRow> {
        self.db.collection(&format!("{}~{}", database.project_id, database.database_id))
    }

    /// A session for running a multi-document transaction (the commit path).
    pub async fn start_session(&self) -> Result<ClientSession, EngineError> {
        Ok(self.db.client().start_session().await?)
    }

    pub async fn get_document(
        &self,
        database: &DatabaseName,
        path: &ResourcePath,
    ) -> Result<Option<StoredDocument>, EngineError> {
        self.get_document_opt(None, database, path).await
    }

    /// As `get_document`, but reading inside `session`'s transaction so the
    /// commit path validates preconditions against the same snapshot it
    /// writes to.
    pub async fn get_document_in_session(
        &self,
        session: &mut ClientSession,
        database: &DatabaseName,
        path: &ResourcePath,
    ) -> Result<Option<StoredDocument>, EngineError> {
        self.get_document_opt(Some(session), database, path).await
    }

    async fn get_document_opt(
        &self,
        session: Option<&mut ClientSession>,
        database: &DatabaseName,
        path: &ResourcePath,
    ) -> Result<Option<StoredDocument>, EngineError> {
        let collection = self.collection(database);
        let find = collection.find_one(doc! { "_id": path.to_string() });
        let row = match session {
            Some(session) => find.session(session).await?,
            None => find.await?,
        };
        row.map(decode_row).transpose()
    }

    /// Unconditional set (create or replace). Preserves `create_time` on
    /// replace via `$setOnInsert`; preconditions and transforms layer on in
    /// the commit path.
    pub async fn set_document(
        &self,
        database: &DatabaseName,
        path: &ResourcePath,
        fields: HashMap<String, Value>,
        now_us: i64,
    ) -> Result<StoredDocument, EngineError> {
        self.set_document_opt(None, database, path, fields, now_us).await
    }

    /// As `set_document`, but written inside `session`'s transaction so the
    /// whole commit lands or none of it does.
    pub async fn set_document_in_session(
        &self,
        session: &mut ClientSession,
        database: &DatabaseName,
        path: &ResourcePath,
        fields: HashMap<String, Value>,
        now_us: i64,
    ) -> Result<StoredDocument, EngineError> {
        self.set_document_opt(Some(session), database, path, fields, now_us).await
    }

    async fn set_document_opt(
        &self,
        session: Option<&mut ClientSession>,
        database: &DatabaseName,
        path: &ResourcePath,
        fields: HashMap<String, Value>,
        now_us: i64,
    ) -> Result<StoredDocument, EngineError> {
        assert!(path.is_document(), "not a document path: {path}");
        let payload = Document { fields: fields.clone(), ..Default::default() }.encode_to_vec();
        let indexed = index_entries(database, path, &fields);
        let collection_path = path.parent().expect("document has a parent");

        let update = doc! {
            "$set": {
                "collection_path": collection_path.to_string(),
                "collection_id": collection_path.last_id().unwrap_or_default(),
                "update_time_us": now_us,
                "payload": Binary { subtype: BinarySubtype::Generic, bytes: payload },
                "indexed": to_bson(&indexed).map_err(|e| {
                    EngineError::InvalidArgument(format!("index entries: {e}"))
                })?,
            },
            "$setOnInsert": { "create_time_us": now_us },
        };
        let collection = self.collection(database);
        let update = collection
            .find_one_and_update(doc! { "_id": path.to_string() }, update)
            .upsert(true)
            .return_document(ReturnDocument::After);
        let row = match session {
            Some(session) => update.session(session).await?,
            None => update.await?,
        };
        decode_row(row.expect("upsert returns a document"))
    }

    /// All documents in one collection (unsorted; callers order).
    pub async fn list_collection(
        &self,
        database: &DatabaseName,
        collection_path: &ResourcePath,
    ) -> Result<Vec<StoredDocument>, EngineError> {
        self.collect_rows(
            self.collection(database)
                .find(doc! { "collection_path": collection_path.to_string() })
                .await?,
        )
        .await
    }

    /// All documents in every collection with this id (collection group).
    pub async fn list_collection_group(
        &self,
        database: &DatabaseName,
        collection_id: &str,
    ) -> Result<Vec<StoredDocument>, EngineError> {
        self.collect_rows(
            self.collection(database).find(doc! { "collection_id": collection_id }).await?,
        )
        .await
    }

    /// Distinct collection ids directly under `parent` (the documents root
    /// or a document path).
    pub async fn list_collection_ids(
        &self,
        database: &DatabaseName,
        parent: &ResourcePath,
    ) -> Result<Vec<String>, EngineError> {
        let paths = self.collection(database).distinct("collection_path", doc! {}).await?;
        let prefix = if parent.is_empty() { String::new() } else { format!("{parent}/") };
        let mut ids: Vec<String> = paths
            .into_iter()
            .filter_map(|p| p.as_str().map(str::to_owned))
            .filter_map(|p| {
                let rest = p.strip_prefix(&prefix)?;
                // Directly under the parent = exactly one remaining segment.
                (!rest.is_empty() && !rest.contains('/')).then(|| rest.to_owned())
            })
            .collect();
        ids.dedup();
        Ok(ids)
    }

    async fn collect_rows(
        &self,
        mut cursor: mongodb::Cursor<DocRow>,
    ) -> Result<Vec<StoredDocument>, EngineError> {
        use futures::TryStreamExt;
        let mut out = Vec::new();
        while let Some(row) = cursor.try_next().await? {
            out.push(decode_row(row)?);
        }
        Ok(out)
    }

    /// Drops every document in a database (admin/test reset).
    pub async fn clear_database(&self, database: &DatabaseName) -> Result<(), EngineError> {
        self.collection(database).drop().await?;
        Ok(())
    }

    /// Returns whether the document existed.
    pub async fn delete_document(
        &self,
        database: &DatabaseName,
        path: &ResourcePath,
    ) -> Result<bool, EngineError> {
        self.delete_document_opt(None, database, path).await
    }

    /// As `delete_document`, but inside `session`'s transaction.
    pub async fn delete_document_in_session(
        &self,
        session: &mut ClientSession,
        database: &DatabaseName,
        path: &ResourcePath,
    ) -> Result<bool, EngineError> {
        self.delete_document_opt(Some(session), database, path).await
    }

    async fn delete_document_opt(
        &self,
        session: Option<&mut ClientSession>,
        database: &DatabaseName,
        path: &ResourcePath,
    ) -> Result<bool, EngineError> {
        let collection = self.collection(database);
        let delete = collection.delete_one(doc! { "_id": path.to_string() });
        let result = match session {
            Some(session) => delete.session(session).await?,
            None => delete.await?,
        };
        Ok(result.deleted_count > 0)
    }
}

fn decode_row(row: DocRow) -> Result<StoredDocument, EngineError> {
    let document = Document::decode(row.payload.bytes.as_slice())
        .map_err(|e| EngineError::InvalidArgument(format!("corrupt payload: {e}")))?;
    Ok(StoredDocument {
        path: ResourcePath::parse(&row.id)?,
        create_time_us: row.create_time_us,
        update_time_us: row.update_time_us,
        fields: document.fields,
    })
}

fn index_entries(
    database: &DatabaseName,
    path: &ResourcePath,
    fields: &HashMap<String, Value>,
) -> Vec<IndexEntry> {
    let name = Value {
        value_type: Some(ValueType::ReferenceValue(format!(
            "{}/{}",
            database.documents_root(),
            path
        ))),
    };
    let mut out =
        vec![IndexEntry { p: "__name__".into(), k: "v", v: to_index_string(&encode_value(&name)) }];
    for (field, value) in fields {
        // TODO(field-paths): escape components needing backticks; plain
        // dotted join for now.
        add_entries(&mut out, field.clone(), value);
    }
    out
}

fn add_entries(out: &mut Vec<IndexEntry>, path: String, value: &Value) {
    out.push(IndexEntry { p: path.clone(), k: "v", v: to_index_string(&encode_value(value)) });
    match value.value_type.as_ref() {
        Some(ValueType::ArrayValue(a)) => {
            for element in &a.values {
                out.push(IndexEntry {
                    p: path.clone(),
                    k: "e",
                    v: to_index_string(&encode_value(element)),
                });
            }
        }
        Some(ValueType::MapValue(m)) => {
            for (k, v) in &m.fields {
                add_entries(out, format!("{path}.{k}"), v);
            }
        }
        _ => {}
    }
}
