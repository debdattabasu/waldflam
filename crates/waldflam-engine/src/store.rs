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

use mongodb::bson::spec::BinarySubtype;
use mongodb::bson::{Binary, doc, to_bson};
use mongodb::options::ReturnDocument;
use mongodb::{Client, Collection, Database};
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

#[derive(Clone)]
pub struct Store {
    db: Database,
}

impl Store {
    pub async fn connect(uri: &str) -> Result<Self, EngineError> {
        let client = Client::with_uri_str(uri).await?;
        Ok(Self { db: client.database("waldflam") })
    }

    fn collection(&self, database: &DatabaseName) -> Collection<DocRow> {
        self.db
            .collection(&format!("{}~{}", database.project_id, database.database_id))
    }

    pub async fn get_document(
        &self,
        database: &DatabaseName,
        path: &ResourcePath,
    ) -> Result<Option<StoredDocument>, EngineError> {
        let row = self
            .collection(database)
            .find_one(doc! { "_id": path.to_string() })
            .await?;
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
        assert!(path.is_document(), "not a document path: {path}");
        let payload = Document {
            fields: fields.clone(),
            ..Default::default()
        }
        .encode_to_vec();
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
        let row = self
            .collection(database)
            .find_one_and_update(doc! { "_id": path.to_string() }, update)
            .upsert(true)
            .return_document(ReturnDocument::After)
            .await?
            .expect("upsert returns a document");
        decode_row(row)
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
            self.collection(database)
                .find(doc! { "collection_id": collection_id })
                .await?,
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
        let paths = self
            .collection(database)
            .distinct("collection_path", doc! {})
            .await?;
        let prefix = if parent.is_empty() {
            String::new()
        } else {
            format!("{parent}/")
        };
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
        let result = self
            .collection(database)
            .delete_one(doc! { "_id": path.to_string() })
            .await?;
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
    let mut out = vec![IndexEntry {
        p: "__name__".into(),
        k: "v",
        v: to_index_string(&encode_value(&name)),
    }];
    for (field, value) in fields {
        // TODO(field-paths): escape components needing backticks; plain
        // dotted join for now.
        add_entries(&mut out, field.clone(), value);
    }
    out
}

fn add_entries(out: &mut Vec<IndexEntry>, path: String, value: &Value) {
    out.push(IndexEntry {
        p: path.clone(),
        k: "v",
        v: to_index_string(&encode_value(value)),
    });
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
