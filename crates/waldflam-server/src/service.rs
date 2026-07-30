use std::pin::Pin;

use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};
use waldflam_proto::v1::firestore_server::Firestore;
use waldflam_proto::v1::*;

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

/// The `google.firestore.v1.Firestore` service.
///
/// Every method is a stub for now; they light up milestone by milestone
/// (docs/architecture.md §9).
#[derive(Debug, Default)]
pub struct FirestoreService {}

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
        _request: Request<GetDocumentRequest>,
    ) -> Result<Response<Document>, Status> {
        Err(Status::unimplemented("GetDocument"))
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
