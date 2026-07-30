use std::pin::Pin;

use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};
use waldflam_engine::path::ResourceName;
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
        InvalidArgument(m) => Status::invalid_argument(m),
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
        _request: Request<BatchGetDocumentsRequest>,
    ) -> Result<Response<Self::BatchGetDocumentsStream>, Status> {
        Err(Status::unimplemented("BatchGetDocuments"))
    }

    async fn begin_transaction(
        &self,
        _request: Request<BeginTransactionRequest>,
    ) -> Result<Response<BeginTransactionResponse>, Status> {
        Err(Status::unimplemented("BeginTransaction"))
    }

    async fn commit(
        &self,
        _request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        Err(Status::unimplemented("Commit"))
    }

    async fn rollback(
        &self,
        _request: Request<RollbackRequest>,
    ) -> Result<Response<()>, Status> {
        Err(Status::unimplemented("Rollback"))
    }

    async fn run_query(
        &self,
        _request: Request<RunQueryRequest>,
    ) -> Result<Response<Self::RunQueryStream>, Status> {
        Err(Status::unimplemented("RunQuery"))
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
