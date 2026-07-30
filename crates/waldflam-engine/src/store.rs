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
//! - `keys`: a nested mirror of the document's fields, each node holding its
//!   own order-preserving index key under `__val__` — so `keys.meta.__val__`
//!   is the map's key and `keys.meta.group.__val__` its child's. Real fields
//!   rather than an array, because MongoDB can sort from an index only on a
//!   stored path; a wildcard index over `keys` keeps that automatic for
//!   schemaless documents.
//! - `name_key`: the `__name__` key, top-level so it can be the trailing
//!   column of those indexes and serve Firestore's implicit `__name__`
//!   tiebreak without a blocking sort.
//! - `elements`: `{p, v}` per array element, for `array-contains` — a sort
//!   column holds one key per document, so membership needs its own entries.

use std::collections::HashMap;
use std::sync::Arc;

use mongodb::bson::spec::BinarySubtype;
use mongodb::bson::{Binary, Document as BsonDocument, doc, to_bson};
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
    v: String,
}

/// Holds a node's own encoded key inside the `keys` mirror. Inside
/// Firestore's reserved `__.*__` field-name pattern, so it cannot collide
/// with a user field — and it keeps every queried leaf a string, which is
/// what makes the `$gte: ""` existence bound well-defined.
pub const VALUE_KEY: &str = "__val__";

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

/// Server-side ordering and paging for a query whose predicate is exact.
///
/// Only safe on an exact predicate: applying `limit` before the in-memory
/// pass would otherwise truncate a candidate set that still contains
/// non-matches. See `plan::Plan::exact`.
#[derive(Debug, Clone)]
pub struct SortWindow {
    /// Normalized order-by as (stored key column, ascending) — BSON paths
    /// from `plan::sort_field`, not Firestore field paths. Always ends with
    /// `name_key`, so the order is total.
    pub order_by: Vec<(String, bool)>,
    pub skip: i64,
    pub limit: Option<i64>,
}

#[derive(Clone)]
pub struct Store {
    db: Database,
    /// Identifies this process's commits so the fan-out tail can skip the
    /// ones it published itself (already delivered in-process).
    instance_id: Arc<str>,
    /// Databases whose query indexes this process has already ensured.
    indexed_databases: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
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
            indexed_databases: Default::default(),
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
        let index = index_document(database, path, &fields);
        let collection_path = path.parent().expect("document has a parent");

        let update = doc! {
            "$set": {
                "collection_path": collection_path.to_string(),
                "collection_id": collection_path.last_id().unwrap_or_default(),
                "update_time_us": now_us,
                "payload": Binary { subtype: BinarySubtype::Generic, bytes: payload },
                "keys": index.keys,
                "name_key": index.name_key,
                "elements": to_bson(&index.elements).map_err(|e| {
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
        self.list_collection_where(database, collection_path, None, None).await
    }

    /// As `list_collection`, narrowed by an index predicate from `plan`.
    /// The predicate may over-match; callers still apply exact semantics.
    pub async fn list_collection_where(
        &self,
        database: &DatabaseName,
        collection_path: &ResourcePath,
        predicate: Option<BsonDocument>,
        window: Option<SortWindow>,
    ) -> Result<Vec<StoredDocument>, EngineError> {
        let filter = self
            .narrowed(database, doc! { "collection_path": collection_path.to_string() }, predicate)
            .await?;
        self.fetch(database, filter, window).await
    }

    /// All documents in every collection with this id (collection group).
    pub async fn list_collection_group(
        &self,
        database: &DatabaseName,
        collection_id: &str,
    ) -> Result<Vec<StoredDocument>, EngineError> {
        self.list_collection_group_where(database, collection_id, None, None).await
    }

    /// As `list_collection_group`, narrowed by an index predicate.
    pub async fn list_collection_group_where(
        &self,
        database: &DatabaseName,
        collection_id: &str,
        predicate: Option<BsonDocument>,
        window: Option<SortWindow>,
    ) -> Result<Vec<StoredDocument>, EngineError> {
        let filter =
            self.narrowed(database, doc! { "collection_id": collection_id }, predicate).await?;
        self.fetch(database, filter, window).await
    }

    /// Runs `filter`, optionally ordering and truncating server-side.
    ///
    /// The sort columns are stored index keys, which are order-preserving, so
    /// sorting by key is sorting by value. Keeping them as real fields rather
    /// than computed ones is the whole point: MongoDB can then answer the
    /// sort from the index and stop at `limit`, instead of ranking every
    /// candidate.
    async fn fetch(
        &self,
        database: &DatabaseName,
        filter: BsonDocument,
        window: Option<SortWindow>,
    ) -> Result<Vec<StoredDocument>, EngineError> {
        let collection = self.collection(database);
        let mut find = collection.find(filter);
        if let Some(window) = window {
            let mut sort = BsonDocument::new();
            for (field, ascending) in &window.order_by {
                sort.insert(field, if *ascending { 1 } else { -1 });
            }
            find = find.sort(sort);
            if window.skip > 0 {
                find = find.skip(window.skip as u64);
            }
            if let Some(limit) = window.limit {
                find = find.limit(limit);
            }
        }
        self.collect_rows(find.await?).await
    }

    /// Folds an index predicate into a base filter, ensuring the indexes that
    /// serve it exist first.
    async fn narrowed(
        &self,
        database: &DatabaseName,
        mut base: BsonDocument,
        predicate: Option<BsonDocument>,
    ) -> Result<BsonDocument, EngineError> {
        if let Some(predicate) = predicate {
            self.ensure_query_indexes(database).await?;
            for (key, value) in predicate {
                base.insert(key, value);
            }
        }
        Ok(base)
    }

    /// Creates the indexes the planner's predicates ride on, once per
    /// database per process. Nothing here is user-declared: a *wildcard*
    /// component covers every field path any document happens to have, which
    /// is what keeps indexing automatic for schemaless documents.
    ///
    /// The shape matters. A wildcard component can serve a sort only when the
    /// query also bounds that field path, and only for one wildcard field —
    /// but a trailing *regular* column is allowed, and `name_key` is exactly
    /// the implicit `__name__` tiebreak Firestore appends to every order-by.
    /// So `{scope, keys.$**, name_key}` covers `ORDER BY <any field>, __name__`
    /// without a blocking sort.
    async fn ensure_query_indexes(&self, database: &DatabaseName) -> Result<(), EngineError> {
        let name = format!("{}~{}", database.project_id, database.database_id);
        {
            let done = self.indexed_databases.lock().expect("index cache");
            if done.contains(&name) {
                return Ok(());
            }
        }
        let models = [
            doc! { "collection_path": 1, "keys.$**": 1, "name_key": 1 },
            doc! { "collection_id": 1, "keys.$**": 1, "name_key": 1 },
            // `array-contains` matches per-element entries instead.
            doc! { "collection_path": 1, "elements.p": 1, "elements.v": 1 },
            doc! { "collection_id": 1, "elements.p": 1, "elements.v": 1 },
        ]
        .map(|keys| mongodb::IndexModel::builder().keys(keys).build());
        // Idempotent: a concurrent caller creating the same indexes is fine.
        self.collection(database).create_indexes(models).await?;
        self.indexed_databases.lock().expect("index cache").insert(name);
        Ok(())
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

/// The derived index columns for one document.
struct DocumentIndex {
    /// Nested mirror of the document's field structure, each node carrying
    /// its own encoded key under `VALUE_KEY`.
    keys: BsonDocument,
    /// One entry per array element, for `array-contains`.
    elements: Vec<IndexEntry>,
    /// The document's `__name__` key, kept top-level so it can be the
    /// trailing column of the wildcard indexes and serve the implicit
    /// `__name__` tiebreak.
    name_key: String,
}

fn index_document(
    database: &DatabaseName,
    path: &ResourcePath,
    fields: &HashMap<String, Value>,
) -> DocumentIndex {
    let name = Value {
        value_type: Some(ValueType::ReferenceValue(format!(
            "{}/{}",
            database.documents_root(),
            path
        ))),
    };
    let mut elements = Vec::new();
    let mut keys = BsonDocument::new();
    for (field, value) in fields {
        // TODO(field-paths): escape components needing backticks; a field
        // literally named `a.b` still collides with the map path `a` → `b`.
        keys.insert(field, key_node(value, field, &mut elements));
    }
    DocumentIndex { keys, elements, name_key: to_index_string(&encode_value(&name)) }
}

/// One node of the `keys` mirror: its own key under `VALUE_KEY`, plus a child
/// node per map entry. The sentinel is what lets a map hold both its own
/// encoded value and its children — `keys.meta` cannot be a string and a
/// subdocument at once.
fn key_node(value: &Value, path: &str, elements: &mut Vec<IndexEntry>) -> BsonDocument {
    let mut node = BsonDocument::new();
    node.insert(VALUE_KEY, to_index_string(&encode_value(value)));
    match value.value_type.as_ref() {
        Some(ValueType::ArrayValue(array)) => {
            for element in &array.values {
                elements.push(IndexEntry {
                    p: path.to_owned(),
                    v: to_index_string(&encode_value(element)),
                });
            }
        }
        Some(ValueType::MapValue(map)) => {
            for (name, child) in &map.fields {
                node.insert(name, key_node(child, &format!("{path}.{name}"), elements));
            }
        }
        _ => {}
    }
    node
}
