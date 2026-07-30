//! REST v1 surface (proto3-JSON): what the JS lite SDK uses for everything
//! and the browser full SDK uses for unary RPCs.
//!
//! Contract (docs/architecture.md §3): `POST /v1/{resource}:{method}` with
//! the resource only in the URL (clients strip `database`/`parent` from the
//! body — we inject them back); bodies may arrive as `text/plain` (the JS
//! SDK's CORS-preflight dodge); streaming RPCs return a JSON *array* of
//! response messages; errors are `{"error": {code, message, status}}` with
//! the *string* gRPC code name.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde::Serialize as _;
use tonic::Status;
use waldflam_proto::v1::firestore_server::Firestore;
use waldflam_proto::v1::*;

use crate::service::FirestoreService;

#[derive(Clone)]
pub struct RestState {
    pub svc: std::sync::Arc<FirestoreService>,
    pub pool: DescriptorPool,
    pub sessions: std::sync::Arc<crate::webchannel::WebChannelSessions>,
    pub triggers: std::sync::Arc<crate::functions::TriggerRegistry>,
}

pub fn descriptor_pool() -> DescriptorPool {
    DescriptorPool::decode(waldflam_proto::FILE_DESCRIPTOR_SET)
        .expect("embedded descriptors decode")
}

/// `POST /v1/{resource}:{method}`.
pub async fn v1_post(
    State(state): State<RestState>,
    Path(path): Path<String>,
    body: Bytes,
) -> Response {
    match dispatch(&state, &path, &body).await {
        Ok(json) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            json,
        )
            .into_response(),
        Err(status) => status_response(&status),
    }
}

async fn dispatch(state: &RestState, path: &str, body: &[u8]) -> Result<String, Status> {
    let (resource, method) = path
        .rsplit_once(':')
        .ok_or_else(|| Status::not_found("unknown REST path"))?;
    let body = if body.is_empty() { b"{}" } else { body };

    match method {
        "commit" => {
            let mut req: CommitRequest = json_to_message(state, "google.firestore.v1.CommitRequest", body)?;
            req.database = database_of(resource)?;
            let resp = state.svc.commit(tonic::Request::new(req)).await?;
            message_to_json(state, "google.firestore.v1.CommitResponse", &resp.into_inner())
        }
        "batchGet" => {
            let mut req: BatchGetDocumentsRequest =
                json_to_message(state, "google.firestore.v1.BatchGetDocumentsRequest", body)?;
            req.database = database_of(resource)?;
            let stream = state
                .svc
                .batch_get_documents(tonic::Request::new(req))
                .await?
                .into_inner();
            collect_json(state, "google.firestore.v1.BatchGetDocumentsResponse", stream).await
        }
        "runQuery" => {
            let mut req: RunQueryRequest =
                json_to_message(state, "google.firestore.v1.RunQueryRequest", body)?;
            req.parent = resource.to_owned();
            let stream = state.svc.run_query(tonic::Request::new(req)).await?.into_inner();
            collect_json(state, "google.firestore.v1.RunQueryResponse", stream).await
        }
        "runAggregationQuery" => {
            let mut req: RunAggregationQueryRequest =
                json_to_message(state, "google.firestore.v1.RunAggregationQueryRequest", body)?;
            req.parent = resource.to_owned();
            let stream = state
                .svc
                .run_aggregation_query(tonic::Request::new(req))
                .await?
                .into_inner();
            collect_json(state, "google.firestore.v1.RunAggregationQueryResponse", stream).await
        }
        "beginTransaction" => {
            let mut req: BeginTransactionRequest =
                json_to_message(state, "google.firestore.v1.BeginTransactionRequest", body)?;
            req.database = database_of(resource)?;
            let resp = state.svc.begin_transaction(tonic::Request::new(req)).await?;
            message_to_json(state, "google.firestore.v1.BeginTransactionResponse", &resp.into_inner())
        }
        "rollback" => {
            let mut req: RollbackRequest =
                json_to_message(state, "google.firestore.v1.RollbackRequest", body)?;
            req.database = database_of(resource)?;
            state.svc.rollback(tonic::Request::new(req)).await?;
            Ok("{}".into())
        }
        _ => Err(Status::not_found(format!("unknown REST method {method:?}"))),
    }
}

/// `projects/p/databases/d/documents` → `projects/p/databases/d`.
fn database_of(resource: &str) -> Result<String, Status> {
    resource
        .strip_suffix("/documents")
        .map(str::to_owned)
        .ok_or_else(|| Status::invalid_argument("expected {database}/documents resource"))
}

pub(crate) fn json_to_message<T: Message + Default>(
    state: &RestState,
    message_name: &str,
    body: &[u8],
) -> Result<T, Status> {
    let descriptor = state
        .pool
        .get_message_by_name(message_name)
        .expect("descriptor present");
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let dynamic = DynamicMessage::deserialize_with_options(
        descriptor,
        &mut deserializer,
        &prost_reflect::DeserializeOptions::new().deny_unknown_fields(false),
    )
    .map_err(|e| Status::invalid_argument(format!("invalid JSON request: {e}")))?;
    T::decode(dynamic.encode_to_vec().as_slice())
        .map_err(|e| Status::internal(format!("transcode: {e}")))
}

pub(crate) fn message_to_json<T: Message>(
    state: &RestState,
    message_name: &str,
    message: &T,
) -> Result<String, Status> {
    let descriptor = state
        .pool
        .get_message_by_name(message_name)
        .expect("descriptor present");
    let dynamic = DynamicMessage::decode(descriptor, message.encode_to_vec().as_slice())
        .map_err(|e| Status::internal(format!("transcode: {e}")))?;
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::new(&mut out);
    dynamic
        .serialize(&mut serializer)
        .map_err(|e| Status::internal(format!("serialize: {e}")))?;
    String::from_utf8(out).map_err(|e| Status::internal(e.to_string()))
}

async fn collect_json<T, S>(state: &RestState, message_name: &str, mut stream: S) -> Result<String, Status>
where
    T: Message,
    S: futures::Stream<Item = Result<T, Status>> + Unpin,
{
    let mut parts = Vec::new();
    while let Some(item) = stream.next().await {
        parts.push(message_to_json(state, message_name, &item?)?);
    }
    Ok(format!("[{}]", parts.join(",")))
}

pub async fn health() -> &'static str {
    "Ok\n"
}

/// `PUT /emulator/v1/projects/{project}:securityRules` — the endpoint
/// `@firebase/rules-unit-testing` uses to load rules. Body:
/// `{"rules": {"files": [{"name": ..., "content": "<rules source>"}]}}`.
pub async fn set_security_rules(
    State(state): State<RestState>,
    Path(project): Path<String>,
    body: Bytes,
) -> Response {
    let project = project.trim_end_matches(":securityRules");
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return status_response(&Status::invalid_argument(format!("invalid JSON: {e}")));
        }
    };
    let source = parsed
        .pointer("/rules/files/0/content")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let ruleset = match waldflam_rules::parse(source) {
        Ok(r) => r,
        Err(issue) => {
            // Match the emulator's compile-error shape.
            return status_response(&Status::invalid_argument(format!(
                "Error compiling rules:\nL{}:{} {}",
                issue.line, issue.col, issue.message
            )));
        }
    };
    // Rules are per-database; the admin API is per-project, so apply to the
    // default database.
    let database = waldflam_engine::path::DatabaseName::new(project, "(default)");
    state.svc.rules.set(&database, ruleset);
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], "{}").into_response()
}

/// `PUT /emulator/v1/projects/{project}/triggers` — registers Cloud
/// Functions triggers. Body: `{"triggers": [{id, pattern, event, endpoint}]}`.
pub async fn set_triggers(State(state): State<RestState>, body: Bytes) -> Response {
    #[derive(serde::Deserialize)]
    struct Body {
        triggers: Vec<crate::functions::TriggerSpec>,
    }
    match serde_json::from_slice::<Body>(&body) {
        Ok(parsed) => {
            let count = parsed.triggers.len();
            state.triggers.replace(parsed.triggers);
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({ "registered": count }).to_string(),
            )
                .into_response()
        }
        Err(e) => status_response(&Status::invalid_argument(format!("invalid triggers: {e}"))),
    }
}

/// `DELETE /emulator/v1/projects/{project}/databases/{db}/documents` —
/// clears all data (test-harness reset).
pub async fn clear_data(
    State(state): State<RestState>,
    Path((project, database)): Path<(String, String)>,
) -> Response {
    let db = waldflam_engine::path::DatabaseName::new(project, database);
    match state.svc.store_handle().clear_database(&db).await {
        Ok(()) => {
            (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], "{}").into_response()
        }
        Err(e) => status_response(&Status::internal(e.to_string())),
    }
}

pub(crate) fn status_response(status: &Status) -> Response {
    let (http, name) = http_code(status.code());
    let body = serde_json::json!({
        "error": {
            "code": http.as_u16(),
            "message": status.message(),
            "status": name,
        }
    });
    (
        http,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// The emulator's gRPC→HTTP mapping (docs/architecture.md §11).
fn http_code(code: tonic::Code) -> (StatusCode, &'static str) {
    use tonic::Code::*;
    match code {
        Ok => (StatusCode::OK, "OK"),
        InvalidArgument => (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT"),
        FailedPrecondition => (StatusCode::BAD_REQUEST, "FAILED_PRECONDITION"),
        OutOfRange => (StatusCode::BAD_REQUEST, "OUT_OF_RANGE"),
        Unauthenticated => (StatusCode::UNAUTHORIZED, "UNAUTHENTICATED"),
        PermissionDenied => (StatusCode::FORBIDDEN, "PERMISSION_DENIED"),
        NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
        Aborted => (StatusCode::CONFLICT, "ABORTED"),
        AlreadyExists => (StatusCode::CONFLICT, "ALREADY_EXISTS"),
        ResourceExhausted => (StatusCode::TOO_MANY_REQUESTS, "RESOURCE_EXHAUSTED"),
        Cancelled => (StatusCode::from_u16(499).unwrap(), "CANCELLED"),
        DataLoss => (StatusCode::INTERNAL_SERVER_ERROR, "DATA_LOSS"),
        Unknown => (StatusCode::INTERNAL_SERVER_ERROR, "UNKNOWN"),
        Internal => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL"),
        Unimplemented => (StatusCode::NOT_IMPLEMENTED, "UNIMPLEMENTED"),
        Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE"),
        DeadlineExceeded => (StatusCode::GATEWAY_TIMEOUT, "DEADLINE_EXCEEDED"),
    }
}

/// Permissive CORS, mirroring the emulator: echo the Origin, allow
/// credentials, echo requested headers; preflights answer 200.
pub async fn cors(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let origin = request.headers().get(header::ORIGIN).cloned();
    let requested = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .cloned();
    let mut response = if request.method() == Method::OPTIONS {
        (StatusCode::OK, "").into_response()
    } else {
        next.run(request).await
    };
    if let Some(origin) = origin {
        let headers: &mut HeaderMap = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("DELETE,GET,HEAD,PATCH,POST,PUT,OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("X-HTTP-Session-Id"),
        );
        if let Some(requested) = requested {
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, requested);
        }
    }
    response
}
