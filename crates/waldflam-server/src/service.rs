use std::collections::HashSet;
use std::pin::Pin;

use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};
use waldflam_engine::path::{DatabaseName, ResourceName};
use waldflam_engine::store::{Store, StoredDocument};
use waldflam_proto::v1::firestore_server::Firestore;
use waldflam_proto::v1::*;

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

/// The `google.firestore.v1.Firestore` service; methods light up milestone
/// by milestone (docs/architecture.md §9).
pub struct FirestoreService {
    store: Store,
    txns: std::sync::Arc<waldflam_engine::txn::TransactionManager>,
    hub: std::sync::Arc<waldflam_engine::watch::WatchHub>,
    pub rules: std::sync::Arc<crate::rules::RulesRegistry>,
}

impl FirestoreService {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            txns: Default::default(),
            hub: Default::default(),
            rules: Default::default(),
        }
    }

    /// Rules enforcement for one document access.
    async fn check_access(
        &self,
        auth: &crate::auth::Authorization,
        database: &DatabaseName,
        path: &waldflam_engine::path::ResourcePath,
        operation: waldflam_rules::Operation,
        incoming: Option<&Document>,
        existing: Option<&waldflam_engine::store::StoredDocument>,
    ) -> Result<(), Status> {
        crate::rules::check(
            &self.rules,
            &self.store,
            auth,
            crate::rules::AccessRequest {
                database,
                path,
                operation,
                incoming,
                existing,
            },
        )
        .await
    }

    pub fn store_handle(&self) -> Store {
        self.store.clone()
    }
    pub fn hub_handle(&self) -> std::sync::Arc<waldflam_engine::watch::WatchHub> {
        self.hub.clone()
    }
    pub fn txns_handle(&self) -> std::sync::Arc<waldflam_engine::txn::TransactionManager> {
        self.txns.clone()
    }

    /// Applies one write through the commit machinery (preconditions, watch
    /// fan-out) and returns the resulting document (empty for deletes).
    async fn apply_single_write(
        &self,
        name: &ResourceName,
        write: Write,
    ) -> Result<Response<Document>, Status> {
        let now = now_us();
        let guard = self.txns.commit_lock.lock().await;
        let applied = waldflam_engine::commit::apply_commit(
            &self.store,
            &name.database,
            std::slice::from_ref(&write),
            now,
        )
        .await
        .map_err(engine_status)?;
        drop(guard);
        let result = applied
            .changes
            .iter()
            .find(|delta| delta.path == name.path)
            .and_then(|delta| delta.after.clone());
        self.hub.publish(waldflam_engine::watch::CommitEvent {
            database: name.database.clone(),
            changes: applied.changes,
            commit_us: now,
        });
        Ok(Response::new(match result {
            Some(doc) => to_wire_document(name, doc),
            None => Document { name: name.to_string(), ..Default::default() },
        }))
    }

    fn begin_txn(&self, database: &DatabaseName, options: Option<&TransactionOptions>) -> Vec<u8> {
        let read_only = matches!(
            options.and_then(|o| o.mode.as_ref()),
            Some(transaction_options::Mode::ReadOnly(_))
        );
        // ReadWrite.retry_transaction is accepted and starts fresh.
        self.txns.begin(database, read_only)
    }
}

/// Firestore-style auto id: 20 chars of [A-Za-z0-9].
fn generate_document_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(20);
    let mut hasher = RandomState::new().build_hasher();
    for i in 0..20u64 {
        hasher.write_u64(i.wrapping_add(now_us() as u64));
        out.push(ALPHABET[(hasher.finish() % ALPHABET.len() as u64) as usize] as char);
    }
    out
}

pub(crate) fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_micros() as i64
}

pub(crate) fn timestamp_from_us(us: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: us.div_euclid(1_000_000),
        nanos: (us.rem_euclid(1_000_000) * 1_000) as i32,
    }
}

pub(crate) fn to_wire_document(name: &ResourceName, doc: StoredDocument) -> Document {
    Document {
        name: name.to_string(),
        fields: doc.fields,
        create_time: Some(timestamp_from_us(doc.create_time_us)),
        update_time: Some(timestamp_from_us(doc.update_time_us)),
    }
}

/// Applies a `select` projection: `__name__` alone means key-only; otherwise
/// keep just the selected field paths.
fn project_fields(
    fields: std::collections::HashMap<String, Value>,
    projection: &structured_query::Projection,
) -> std::collections::HashMap<String, Value> {
    let paths: Vec<&str> = projection
        .fields
        .iter()
        .map(|f| f.field_path.as_str())
        .collect();
    if paths.is_empty() {
        return fields;
    }
    let mut out = std::collections::HashMap::new();
    for path in paths {
        if path == "__name__" {
            continue;
        }
        if let Some(v) = waldflam_engine::fields::get_field(&fields, path) {
            waldflam_engine::fields::set_field(&mut out, path, v.clone());
        }
    }
    out
}

/// Applies a read `mask` (ListDocuments/BatchGet): present-but-empty masks
/// return no fields.
fn mask_fields(
    fields: std::collections::HashMap<String, Value>,
    mask: &DocumentMask,
) -> std::collections::HashMap<String, Value> {
    let mut out = std::collections::HashMap::new();
    for path in &mask.field_paths {
        if let Some(v) = waldflam_engine::fields::get_field(&fields, path) {
            waldflam_engine::fields::set_field(&mut out, path, v.clone());
        }
    }
    out
}

pub(crate) fn engine_status(err: waldflam_engine::EngineError) -> Status {
    use waldflam_engine::EngineError::*;
    match err {
        NotFound(m) => Status::not_found(m),
        AlreadyExists(m) => Status::already_exists(m),
        Aborted => Status::aborted("transaction contention"),
        FailedPrecondition(m) => Status::failed_precondition(m),
        InvalidArgument(m) => Status::invalid_argument(m),
        Unimplemented(m) => Status::unimplemented(m),
        Mongo(e) => Status::internal(format!("storage: {e}")),
    }
}

#[tonic::async_trait]
impl Firestore for FirestoreService {
    type BatchGetDocumentsStream = BoxStream<BatchGetDocumentsResponse>;
    type RunQueryStream = BoxStream<RunQueryResponse>;
    type RunAggregationQueryStream = BoxStream<RunAggregationQueryResponse>;
    type ExecutePipelineStream = BoxStream<ExecutePipelineResponse>;
    type WriteStream = BoxStream<WriteResponse>;
    type ListenStream = BoxStream<ListenResponse>;

    async fn get_document(
        &self,
        request: Request<GetDocumentRequest>,
    ) -> Result<Response<Document>, Status> {
        let auth = crate::auth::Authorization::from_metadata(request.metadata())?;
        let req = request.into_inner();
        let not_found = || Status::not_found(format!("Document ({}) not found.", req.name));
        // Anything with a valid database prefix that isn't a document path
        // (e.g. firestore-rs's ping probe) can't exist: NOT_FOUND, not
        // INVALID_ARGUMENT — clients treat the latter as fatal.
        let name = match ResourceName::parse(&req.name) {
            Ok(name) if name.path.is_document() => name,
            Ok(_) => return Err(not_found()),
            Err(_) if DatabaseName::parse_prefix(&req.name).is_ok() => {
                return Err(not_found());
            }
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };
        // TODO(consistency): honor read_time (reads see latest state).
        let doc = self
            .store
            .get_document(&name.database, &name.path)
            .await
            .map_err(engine_status)?;
        if let Some(get_document_request::ConsistencySelector::Transaction(token)) =
            req.consistency_selector.as_ref()
        {
            let version = doc.as_ref().map(|d| d.update_time_us).unwrap_or(0);
            self.txns.record_read(token, name.path.to_string(), version);
        }
        let doc = doc.ok_or_else(not_found)?;
        self.check_access(
            &auth,
            &name.database,
            &name.path,
            waldflam_rules::Operation::Get,
            None,
            Some(&doc),
        )
        .await?;
        Ok(Response::new(to_wire_document(&name, doc)))
    }

    async fn create_document(
        &self,
        request: Request<CreateDocumentRequest>,
    ) -> Result<Response<Document>, Status> {
        let req = request.into_inner();
        let parent = ResourceName::parse(&req.parent)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let document_id = if req.document_id.is_empty() {
            generate_document_id()
        } else {
            req.document_id.clone()
        };
        let path = parent
            .path
            .child(&req.collection_id)
            .and_then(|c| c.child(&document_id))
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let name = ResourceName { database: parent.database, path };
        let mut doc = req.document.unwrap_or_default();
        doc.name = name.to_string();
        let write = Write {
            operation: Some(write::Operation::Update(doc)),
            current_document: Some(Precondition {
                condition_type: Some(precondition::ConditionType::Exists(false)),
            }),
            ..Default::default()
        };
        self.apply_single_write(&name, write).await
    }

    async fn list_documents(
        &self,
        request: Request<ListDocumentsRequest>,
    ) -> Result<Response<ListDocumentsResponse>, Status> {
        let req = request.into_inner();
        let parent = ResourceName::parse(&req.parent)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        if req.collection_id.is_empty() {
            return Err(Status::invalid_argument("missing collection_id"));
        }
        let collection = parent
            .path
            .child(&req.collection_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        // TODO(paging/order_by/show_missing): everything in one page, sorted
        // by __name__; clients stop on the empty next_page_token.
        let mut docs = self
            .store
            .list_collection(&parent.database, &collection)
            .await
            .map_err(engine_status)?;
        docs.sort_by(|a, b| a.path.cmp(&b.path));
        let documents = docs
            .into_iter()
            .map(|doc| {
                let name = ResourceName {
                    database: parent.database.clone(),
                    path: doc.path.clone(),
                };
                let mut wire = to_wire_document(&name, doc);
                if let Some(mask) = req.mask.as_ref() {
                    wire.fields = mask_fields(wire.fields, mask);
                }
                wire
            })
            .collect();
        Ok(Response::new(ListDocumentsResponse {
            documents,
            next_page_token: String::new(),
        }))
    }

    async fn update_document(
        &self,
        request: Request<UpdateDocumentRequest>,
    ) -> Result<Response<Document>, Status> {
        let req = request.into_inner();
        let doc = req.document.unwrap_or_default();
        let name = ResourceName::parse_document(&doc.name)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let write = Write {
            operation: Some(write::Operation::Update(doc)),
            update_mask: req.update_mask,
            current_document: req.current_document,
            ..Default::default()
        };
        self.apply_single_write(&name, write).await
    }

    async fn delete_document(
        &self,
        request: Request<DeleteDocumentRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let name = ResourceName::parse_document(&req.name)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let write = Write {
            operation: Some(write::Operation::Delete(req.name)),
            current_document: req.current_document,
            ..Default::default()
        };
        self.apply_single_write(&name, write).await?;
        Ok(Response::new(()))
    }

    async fn batch_get_documents(
        &self,
        request: Request<BatchGetDocumentsRequest>,
    ) -> Result<Response<Self::BatchGetDocumentsStream>, Status> {
        let auth = crate::auth::Authorization::from_metadata(request.metadata())?;
        let req = request.into_inner();
        let database = DatabaseName::parse(&req.database)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let read_time = timestamp_from_us(now_us());

        // Transaction handling: record reads into an existing transaction,
        // or begin one for new_transaction (its id rides on the first
        // response). TODO(consistency): read_time reads see latest state.
        use batch_get_documents_request::ConsistencySelector as Sel;
        let (txn_token, new_txn) = match req.consistency_selector.as_ref() {
            Some(Sel::Transaction(t)) => (Some(t.clone()), None),
            Some(Sel::NewTransaction(opts)) => {
                let token = self.begin_txn(&database, Some(opts));
                (Some(token.clone()), Some(token))
            }
            _ => (None, None),
        };

        // Each distinct name gets exactly one found/missing answer (the Go
        // client fans a single answer out to duplicate request entries).
        let mut seen = HashSet::new();
        let mut responses = Vec::new();
        for name in &req.documents {
            if !seen.insert(name.clone()) {
                continue;
            }
            let parsed = ResourceName::parse_document(name)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;
            let doc = self
                .store
                .get_document(&database, &parsed.path)
                .await
                .map_err(engine_status)?;
            if let Some(token) = txn_token.as_ref() {
                let version = doc.as_ref().map(|d| d.update_time_us).unwrap_or(0);
                self.txns.record_read(token, parsed.path.to_string(), version);
            }
            if let Some(found) = doc.as_ref() {
                self.check_access(
                    &auth,
                    &database,
                    &parsed.path,
                    waldflam_rules::Operation::Get,
                    None,
                    Some(found),
                )
                .await?;
            }
            let result = match doc {
                Some(doc) => batch_get_documents_response::Result::Found(
                    to_wire_document(&parsed, doc),
                ),
                None => batch_get_documents_response::Result::Missing(name.clone()),
            };
            responses.push(Ok(BatchGetDocumentsResponse {
                result: Some(result),
                read_time: Some(read_time),
                transaction: if responses.is_empty() {
                    new_txn.clone().unwrap_or_default()
                } else {
                    Vec::new()
                },
            }));
        }
        Ok(Response::new(Box::pin(tokio_stream::iter(responses))))
    }

    async fn begin_transaction(
        &self,
        request: Request<BeginTransactionRequest>,
    ) -> Result<Response<BeginTransactionResponse>, Status> {
        let req = request.into_inner();
        let database = DatabaseName::parse(&req.database)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        Ok(Response::new(BeginTransactionResponse {
            transaction: self.begin_txn(&database, req.options.as_ref()),
        }))
    }

    async fn commit(
        &self,
        request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        let auth = crate::auth::Authorization::from_metadata(request.metadata())?;
        let req = request.into_inner();
        let database = DatabaseName::parse(&req.database)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let now = now_us();

        crate::rules::check_writes(&self.rules, &self.store, &auth, &database, &req.writes)
            .await?;

        // The commit lock serializes validate+apply across all commits so a
        // transaction can't be invalidated between its validation and write.
        let _commit_guard = self.txns.commit_lock.lock().await;
        if !req.transaction.is_empty() {
            let state = self
                .txns
                .take(&req.transaction, &database)
                .map_err(engine_status)?;
            if state.read_only && !req.writes.is_empty() {
                return Err(Status::invalid_argument(
                    "read-only transaction cannot write",
                ));
            }
            waldflam_engine::txn::validate_read_set(&self.store, &state)
                .await
                .map_err(engine_status)?;
        }
        let applied =
            waldflam_engine::commit::apply_commit(&self.store, &database, &req.writes, now)
                .await
                .map_err(engine_status)?;
        self.hub.publish(waldflam_engine::watch::CommitEvent {
            database,
            changes: applied.changes,
            commit_us: now,
        });
        Ok(Response::new(CommitResponse {
            write_results: applied
                .outcomes
                .into_iter()
                .map(|o| WriteResult {
                    update_time: Some(timestamp_from_us(o.update_time_us)),
                    transform_results: o.transform_results,
                })
                .collect(),
            commit_time: Some(timestamp_from_us(now)),
        }))
    }

    async fn rollback(
        &self,
        request: Request<RollbackRequest>,
    ) -> Result<Response<()>, Status> {
        // Rollback is best-effort and idempotent (clients fire-and-forget it
        // on detached contexts): unknown ids are fine.
        self.txns.rollback(&request.into_inner().transaction);
        Ok(Response::new(()))
    }

    async fn run_query(
        &self,
        request: Request<RunQueryRequest>,
    ) -> Result<Response<Self::RunQueryStream>, Status> {
        let auth = crate::auth::Authorization::from_metadata(request.metadata())?;
        let req = request.into_inner();
        let parent = ResourceName::parse(&req.parent)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let Some(run_query_request::QueryType::StructuredQuery(query)) = req.query_type else {
            return Err(Status::invalid_argument("missing structured_query"));
        };
        use run_query_request::ConsistencySelector as Sel;
        let (txn_token, new_txn) = match req.consistency_selector.as_ref() {
            Some(Sel::Transaction(t)) => (Some(t.clone()), None),
            Some(Sel::NewTransaction(opts)) => {
                let token = self.begin_txn(&parent.database, Some(opts));
                (Some(token.clone()), Some(token))
            }
            _ => (None, None), // TODO(consistency): read_time sees latest
        };
        if let Some(selector) = query.from.first() {
            let collection = parent
                .path
                .child(&selector.collection_id)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;
            self.check_access(
                &auth,
                &parent.database,
                &collection,
                waldflam_rules::Operation::List,
                None,
                None,
            )
            .await?;
        }
        let docs =
            waldflam_engine::query::run_query(&self.store, &parent.database, &parent.path, &query)
                .await
                .map_err(engine_status)?;
        if let Some(token) = txn_token.as_ref() {
            for doc in &docs {
                self.txns
                    .record_read(token, doc.path.to_string(), doc.update_time_us);
            }
        }

        let read_time = timestamp_from_us(now_us());
        let select = query.select.as_ref();
        let mut responses: Vec<Result<RunQueryResponse, Status>> = docs
            .into_iter()
            .enumerate()
            .map(|(i, doc)| {
                let name = ResourceName { database: parent.database.clone(), path: doc.path.clone() };
                let mut wire = to_wire_document(&name, doc);
                if let Some(projection) = select {
                    wire.fields = project_fields(wire.fields, projection);
                }
                Ok(RunQueryResponse {
                    document: Some(wire),
                    read_time: Some(read_time),
                    transaction: if i == 0 {
                        new_txn.clone().unwrap_or_default()
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                })
            })
            .collect();
        if responses.is_empty() {
            // No results: a single read_time-only response, then EOF.
            responses.push(Ok(RunQueryResponse {
                read_time: Some(read_time),
                transaction: new_txn.unwrap_or_default(),
                ..Default::default()
            }));
        }
        Ok(Response::new(Box::pin(tokio_stream::iter(responses))))
    }

    async fn run_aggregation_query(
        &self,
        request: Request<RunAggregationQueryRequest>,
    ) -> Result<Response<Self::RunAggregationQueryStream>, Status> {
        let req = request.into_inner();
        let parent = ResourceName::parse(&req.parent)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let Some(run_aggregation_query_request::QueryType::StructuredAggregationQuery(agg_query)) =
            req.query_type
        else {
            return Err(Status::invalid_argument("missing structured_aggregation_query"));
        };
        let Some(structured_aggregation_query::QueryType::StructuredQuery(query)) =
            agg_query.query_type
        else {
            return Err(Status::invalid_argument("missing underlying structured_query"));
        };
        // TODO(consistency): transaction / read_time selectors.
        let docs =
            waldflam_engine::query::run_query(&self.store, &parent.database, &parent.path, &query)
                .await
                .map_err(engine_status)?;
        let results = waldflam_engine::query::aggregate(&docs, &agg_query.aggregations)
            .map_err(engine_status)?;

        // One response carrying every aggregate satisfies all SDK contracts
        // (JS asserts exactly one result; Go merges across responses).
        let response = RunAggregationQueryResponse {
            result: Some(AggregationResult {
                aggregate_fields: results.into_iter().collect(),
            }),
            read_time: Some(timestamp_from_us(now_us())),
            ..Default::default()
        };
        Ok(Response::new(Box::pin(tokio_stream::iter(vec![Ok(response)]))))
    }

    async fn execute_pipeline(
        &self,
        _request: Request<ExecutePipelineRequest>,
    ) -> Result<Response<Self::ExecutePipelineStream>, Status> {
        Err(Status::unimplemented("ExecutePipeline"))
    }

    async fn partition_query(
        &self,
        _request: Request<PartitionQueryRequest>,
    ) -> Result<Response<PartitionQueryResponse>, Status> {
        Err(Status::unimplemented("PartitionQuery"))
    }

    async fn write(
        &self,
        request: Request<Streaming<WriteRequest>>,
    ) -> Result<Response<Self::WriteStream>, Status> {
        let auth = crate::auth::Authorization::from_metadata(request.metadata())?;
        let stream = crate::write_stream::spawn(
            self.store.clone(),
            self.hub.clone(),
            self.txns.clone(),
            auth,
            self.rules.clone(),
            request.into_inner(),
        );
        Ok(Response::new(Box::pin(stream)))
    }

    async fn listen(
        &self,
        request: Request<Streaming<ListenRequest>>,
    ) -> Result<Response<Self::ListenStream>, Status> {
        let auth = crate::auth::Authorization::from_metadata(request.metadata())?;
        let stream = crate::listen::spawn(
            self.store.clone(),
            self.hub.clone(),
            auth,
            self.rules.clone(),
            request.into_inner(),
        );
        Ok(Response::new(Box::pin(stream)))
    }

    async fn list_collection_ids(
        &self,
        request: Request<ListCollectionIdsRequest>,
    ) -> Result<Response<ListCollectionIdsResponse>, Status> {
        let req = request.into_inner();
        let parent = ResourceName::parse(&req.parent)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mut ids = self
            .store
            .list_collection_ids(&parent.database, &parent.path)
            .await
            .map_err(engine_status)?;
        ids.sort();
        Ok(Response::new(ListCollectionIdsResponse {
            collection_ids: ids,
            next_page_token: String::new(),
        }))
    }

    async fn batch_write(
        &self,
        _request: Request<BatchWriteRequest>,
    ) -> Result<Response<BatchWriteResponse>, Status> {
        Err(Status::unimplemented("BatchWrite"))
    }

}
