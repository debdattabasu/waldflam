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
}

impl FirestoreService {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_micros() as i64
}

fn timestamp_from_us(us: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: us.div_euclid(1_000_000),
        nanos: (us.rem_euclid(1_000_000) * 1_000) as i32,
    }
}

fn to_wire_document(name: &ResourceName, doc: StoredDocument) -> Document {
    Document {
        name: name.to_string(),
        fields: doc.fields,
        create_time: Some(timestamp_from_us(doc.create_time_us)),
        update_time: Some(timestamp_from_us(doc.update_time_us)),
    }
}

fn engine_status(err: waldflam_engine::EngineError) -> Status {
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
        let req = request.into_inner();
        let not_found = || Status::not_found(format!("Document ({}) not found.", req.name));
        let name = ResourceName::parse(&req.name)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        // A parseable name that isn't a document path (e.g. firestore-rs's
        // `-ping-` probe) can't exist: NOT_FOUND, not INVALID_ARGUMENT.
        if !name.path.is_document() {
            return Err(not_found());
        }
        // TODO(consistency): honor transaction / read_time selectors.
        let doc = self
            .store
            .get_document(&name.database, &name.path)
            .await
            .map_err(engine_status)?
            .ok_or_else(not_found)?;
        Ok(Response::new(to_wire_document(&name, doc)))
    }

    async fn list_documents(
        &self,
        _request: Request<ListDocumentsRequest>,
    ) -> Result<Response<ListDocumentsResponse>, Status> {
        Err(Status::unimplemented("ListDocuments"))
    }

    async fn update_document(
        &self,
        _request: Request<UpdateDocumentRequest>,
    ) -> Result<Response<Document>, Status> {
        Err(Status::unimplemented("UpdateDocument"))
    }

    async fn delete_document(
        &self,
        _request: Request<DeleteDocumentRequest>,
    ) -> Result<Response<()>, Status> {
        Err(Status::unimplemented("DeleteDocument"))
    }

    async fn batch_get_documents(
        &self,
        request: Request<BatchGetDocumentsRequest>,
    ) -> Result<Response<Self::BatchGetDocumentsStream>, Status> {
        let req = request.into_inner();
        let database = DatabaseName::parse(&req.database)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let read_time = timestamp_from_us(now_us());

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
            // TODO(consistency): honor transaction / new_transaction / read_time.
            let result = match self
                .store
                .get_document(&database, &parsed.path)
                .await
                .map_err(engine_status)?
            {
                Some(doc) => batch_get_documents_response::Result::Found(
                    to_wire_document(&parsed, doc),
                ),
                None => batch_get_documents_response::Result::Missing(name.clone()),
            };
            responses.push(Ok(BatchGetDocumentsResponse {
                result: Some(result),
                read_time: Some(read_time),
                ..Default::default()
            }));
        }
        Ok(Response::new(Box::pin(tokio_stream::iter(responses))))
    }

    async fn begin_transaction(
        &self,
        _request: Request<BeginTransactionRequest>,
    ) -> Result<Response<BeginTransactionResponse>, Status> {
        Err(Status::unimplemented("BeginTransaction"))
    }

    async fn commit(
        &self,
        request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        let req = request.into_inner();
        if !req.transaction.is_empty() {
            return Err(Status::unimplemented("transactional commits (M2)"));
        }
        let database = DatabaseName::parse(&req.database)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let now = now_us();
        let outcomes =
            waldflam_engine::commit::apply_commit(&self.store, &database, &req.writes, now)
                .await
                .map_err(engine_status)?;
        Ok(Response::new(CommitResponse {
            write_results: outcomes
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
        _request: Request<RollbackRequest>,
    ) -> Result<Response<()>, Status> {
        Err(Status::unimplemented("Rollback"))
    }

    async fn run_query(
        &self,
        request: Request<RunQueryRequest>,
    ) -> Result<Response<Self::RunQueryStream>, Status> {
        let req = request.into_inner();
        let parent = ResourceName::parse(&req.parent)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let Some(run_query_request::QueryType::StructuredQuery(query)) = req.query_type else {
            return Err(Status::invalid_argument("missing structured_query"));
        };
        // TODO(consistency): honor transaction / new_transaction / read_time.
        let docs =
            waldflam_engine::query::run_query(&self.store, &parent.database, &parent.path, &query)
                .await
                .map_err(engine_status)?;

        let read_time = timestamp_from_us(now_us());
        let mut responses: Vec<Result<RunQueryResponse, Status>> = docs
            .into_iter()
            .map(|doc| {
                let name = ResourceName { database: parent.database.clone(), path: doc.path.clone() };
                Ok(RunQueryResponse {
                    document: Some(to_wire_document(&name, doc)),
                    read_time: Some(read_time),
                    ..Default::default()
                })
            })
            .collect();
        if responses.is_empty() {
            // No results: a single read_time-only response, then EOF.
            responses.push(Ok(RunQueryResponse {
                read_time: Some(read_time),
                ..Default::default()
            }));
        }
        Ok(Response::new(Box::pin(tokio_stream::iter(responses))))
    }

    async fn run_aggregation_query(
        &self,
        _request: Request<RunAggregationQueryRequest>,
    ) -> Result<Response<Self::RunAggregationQueryStream>, Status> {
        Err(Status::unimplemented("RunAggregationQuery"))
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
        _request: Request<Streaming<WriteRequest>>,
    ) -> Result<Response<Self::WriteStream>, Status> {
        Err(Status::unimplemented("Write"))
    }

    async fn listen(
        &self,
        _request: Request<Streaming<ListenRequest>>,
    ) -> Result<Response<Self::ListenStream>, Status> {
        Err(Status::unimplemented("Listen"))
    }

    async fn list_collection_ids(
        &self,
        _request: Request<ListCollectionIdsRequest>,
    ) -> Result<Response<ListCollectionIdsResponse>, Status> {
        Err(Status::unimplemented("ListCollectionIds"))
    }

    async fn batch_write(
        &self,
        _request: Request<BatchWriteRequest>,
    ) -> Result<Response<BatchWriteResponse>, Status> {
        Err(Status::unimplemented("BatchWrite"))
    }

    async fn create_document(
        &self,
        _request: Request<CreateDocumentRequest>,
    ) -> Result<Response<Document>, Status> {
        Err(Status::unimplemented("CreateDocument"))
    }
}
