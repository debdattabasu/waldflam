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
    pub credentials: std::sync::Arc<crate::credentials::Credentials>,
}

/// Carries the caller's credentials into the gRPC request the service sees.
///
/// Without this the REST surface authenticates as nobody: the service reads
/// `authorization` from request metadata, and a `tonic::Request` built from a
/// message alone has none — so a signed-in user's rules would evaluate with
/// `request.auth == null`, and `Bearer owner` would not grant admin.
fn authed<T>(message: T, headers: &HeaderMap) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    if let Some(value) = headers.get(header::AUTHORIZATION)
        && let Ok(text) = value.to_str()
        && let Ok(metadata) = text.parse()
    {
        request.metadata_mut().insert("authorization", metadata);
    }
    request
}

/// Guards the `/emulator/v1` endpoints, which load rules, register trigger
/// callbacks, and erase whole databases.
///
/// The emulator leaves these open because it is a local development tool; a
/// server anyone can reach must not, so verified mode requires admin. In
/// emulator mode this is a no-op, keeping the SDK test harnesses working.
async fn require_admin(
    state: &RestState,
    headers: &HeaderMap,
    project: &str,
) -> Result<(), Response> {
    if !state.svc.auth.guards_admin_api() {
        return Ok(());
    }
    let header = headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok());
    // Scoped to the project in the URL: a service account for one project
    // must not be able to load rules into — or erase — another's.
    match state.svc.auth.authorize(header).await.map(|auth| auth.for_project(project)) {
        Ok(crate::auth::Authorization::Admin(_)) => Ok(()),
        _ => Err(status_response(&Status::permission_denied(
            "admin credentials required for this endpoint",
        ))),
    }
}

pub fn descriptor_pool() -> DescriptorPool {
    DescriptorPool::decode(waldflam_proto::FILE_DESCRIPTOR_SET)
        .expect("embedded descriptors decode")
}

/// `POST /v1/{resource}:{method}`.
pub async fn v1_post(
    State(state): State<RestState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Identity endpoints share the `/v1/` prefix with Firestore's REST
    // surface but are not Firestore RPCs, so they are answered before the
    // proto3-JSON dispatcher — which would read them as `resource:method`.
    match path.as_str() {
        "accounts:signInWithCustomToken" => return sign_in_with_custom_token(&state, &body).await,
        "token" => return refresh_token(&state, &body).await,
        _ => {}
    }
    match dispatch(&state, &path, &body, &headers).await {
        Ok(json) => {
            (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], json).into_response()
        }
        Err(status) => status_response(&status),
    }
}

async fn dispatch(
    state: &RestState,
    path: &str,
    body: &[u8],
    headers: &HeaderMap,
) -> Result<String, Status> {
    let (resource, method) =
        path.rsplit_once(':').ok_or_else(|| Status::not_found("unknown REST path"))?;
    let body = if body.is_empty() { b"{}" } else { body };

    match method {
        "commit" => {
            let mut req: CommitRequest =
                json_to_message(state, "google.firestore.v1.CommitRequest", body)?;
            req.database = database_of(resource)?;
            let resp = state.svc.commit(authed(req, headers)).await?;
            message_to_json(state, "google.firestore.v1.CommitResponse", &resp.into_inner())
        }
        "batchGet" => {
            let mut req: BatchGetDocumentsRequest =
                json_to_message(state, "google.firestore.v1.BatchGetDocumentsRequest", body)?;
            req.database = database_of(resource)?;
            let stream = state.svc.batch_get_documents(authed(req, headers)).await?.into_inner();
            collect_json(state, "google.firestore.v1.BatchGetDocumentsResponse", stream).await
        }
        "runQuery" => {
            let mut req: RunQueryRequest =
                json_to_message(state, "google.firestore.v1.RunQueryRequest", body)?;
            req.parent = resource.to_owned();
            let stream = state.svc.run_query(authed(req, headers)).await?.into_inner();
            collect_json(state, "google.firestore.v1.RunQueryResponse", stream).await
        }
        "runAggregationQuery" => {
            let mut req: RunAggregationQueryRequest =
                json_to_message(state, "google.firestore.v1.RunAggregationQueryRequest", body)?;
            req.parent = resource.to_owned();
            let stream = state.svc.run_aggregation_query(authed(req, headers)).await?.into_inner();
            collect_json(state, "google.firestore.v1.RunAggregationQueryResponse", stream).await
        }
        "beginTransaction" => {
            let mut req: BeginTransactionRequest =
                json_to_message(state, "google.firestore.v1.BeginTransactionRequest", body)?;
            req.database = database_of(resource)?;
            let resp = state.svc.begin_transaction(authed(req, headers)).await?;
            message_to_json(
                state,
                "google.firestore.v1.BeginTransactionResponse",
                &resp.into_inner(),
            )
        }
        "rollback" => {
            let mut req: RollbackRequest =
                json_to_message(state, "google.firestore.v1.RollbackRequest", body)?;
            req.database = database_of(resource)?;
            state.svc.rollback(authed(req, headers)).await?;
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
    let descriptor = state.pool.get_message_by_name(message_name).expect("descriptor present");
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
    let descriptor = state.pool.get_message_by_name(message_name).expect("descriptor present");
    let dynamic = DynamicMessage::decode(descriptor, message.encode_to_vec().as_slice())
        .map_err(|e| Status::internal(format!("transcode: {e}")))?;
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::new(&mut out);
    dynamic.serialize(&mut serializer).map_err(|e| Status::internal(format!("serialize: {e}")))?;
    String::from_utf8(out).map_err(|e| Status::internal(e.to_string()))
}

async fn collect_json<T, S>(
    state: &RestState,
    message_name: &str,
    mut stream: S,
) -> Result<String, Status>
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

/// `POST /oauth2/v4/token` — the OAuth2 JWT-bearer grant.
///
/// A Google auth library that honours the key file's `token_uri` lands here:
/// it signs an assertion with the service account's private key and trades it
/// for a short-lived access token. Libraries that instead send the assertion
/// straight through as a bearer are handled too — `auth.rs` accepts either —
/// because which of the two a given client picks is a detail of that
/// client's version, not something a server can insist on.
pub async fn oauth_token(State(state): State<RestState>, body: Bytes) -> Response {
    let form: std::collections::HashMap<String, String> =
        form_urlencoded::parse(&body).into_owned().collect();
    let grant = form.get("grant_type").map(String::as_str).unwrap_or_default();
    if grant != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("expected the jwt-bearer grant, got {grant:?}"),
        );
    }
    let Some(assertion) = form.get("assertion") else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing assertion");
    };
    match state.credentials.exchange_assertion(assertion).await {
        Ok((access_token, expires_in)) => json_ok(serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
        })),
        Err(status) => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", status.message()),
    }
}

/// `GET /.well-known/jwks.json` — the public keys for tokens waldflam issues,
/// so its own verifier and anything else that speaks OIDC can check them.
pub async fn jwks(State(state): State<RestState>) -> Response {
    match state.credentials.jwks().await {
        Ok(keys) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                // Verifiers cache key sets by this header — Google's do, and
                // so does anything following OIDC. It has to stay well under
                // how long a retired key keeps verifying, or a client could
                // still be holding the old set when tokens signed by the new
                // key start arriving.
                (header::CACHE_CONTROL, "public, max-age=300"),
            ],
            keys.to_string(),
        )
            .into_response(),
        Err(status) => status_response(&status),
    }
}

/// `GET /.well-known/openid-configuration` — lets a verifier configure itself
/// from the issuer URL alone.
pub async fn openid_configuration(State(state): State<RestState>) -> Response {
    json_ok(state.credentials.discovery().await)
}

/// `POST /v1/accounts:signInWithCustomToken` — exchanges a custom token
/// minted by a service account for an ID token, in the identitytoolkit
/// response shape the Firebase clients expect.
async fn sign_in_with_custom_token(state: &RestState, body: &[u8]) -> Response {
    #[derive(serde::Deserialize)]
    struct Body {
        token: String,
    }
    let parsed: Body = match serde_json::from_slice(body) {
        Ok(parsed) => parsed,
        Err(e) => {
            return status_response(&Status::invalid_argument(format!("invalid request: {e}")));
        }
    };
    match state.credentials.sign_in_with_custom_token(&parsed.token).await {
        Ok(signed_in) => json_ok(serde_json::json!({
            "kind": "identitytoolkit#VerifyCustomTokenResponse",
            "idToken": signed_in.id_token,
            "refreshToken": signed_in.refresh_token,
            "expiresIn": signed_in.expires_in.to_string(),
            "isNewUser": false,
        })),
        Err(status) => status_response(&status),
    }
}

/// `POST /v1/token` — trades a refresh token for a fresh ID token, in the
/// securetoken response shape.
async fn refresh_token(state: &RestState, body: &[u8]) -> Response {
    // Sent form-encoded by the client SDKs, but accept JSON too since this
    // endpoint is equally likely to be called by hand.
    let token = match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(json) => json.get("refresh_token").and_then(|v| v.as_str()).map(str::to_owned),
        Err(_) => form_urlencoded::parse(body)
            .find(|(key, _)| key == "refresh_token")
            .map(|(_, value)| value.into_owned()),
    };
    let Some(token) = token else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing refresh_token");
    };
    match state.credentials.refresh(&token).await {
        Ok(signed_in) => json_ok(serde_json::json!({
            "access_token": signed_in.id_token,
            "id_token": signed_in.id_token,
            "refresh_token": signed_in.refresh_token,
            "expires_in": signed_in.expires_in.to_string(),
            "token_type": "Bearer",
            "user_id": signed_in.uid,
            "project_id": signed_in.project_id,
        })),
        Err(status) => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", status.message()),
    }
}

fn json_ok(body: serde_json::Value) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], body.to_string()).into_response()
}

/// OAuth2's own error shape, which is not the Google API one — a client's
/// token machinery parses this, not `{"error": {...}}`.
fn oauth_error(code: StatusCode, error: &str, description: &str) -> Response {
    let body = serde_json::json!({ "error": error, "error_description": description });
    (code, [(header::CONTENT_TYPE, "application/json")], body.to_string()).into_response()
}

/// `PUT /emulator/v1/projects/{project}:securityRules` — the endpoint
/// `@firebase/rules-unit-testing` uses to load rules. Body:
/// `{"rules": {"files": [{"name": ..., "content": "<rules source>"}]}}`.
pub async fn set_security_rules(
    State(state): State<RestState>,
    Path(project): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let project = project.trim_end_matches(":securityRules");
    if let Err(denied) = require_admin(&state, &headers, project).await {
        return denied;
    }
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return status_response(&Status::invalid_argument(format!("invalid JSON: {e}")));
        }
    };
    let source =
        parsed.pointer("/rules/files/0/content").and_then(|v| v.as_str()).unwrap_or_default();
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
pub async fn set_triggers(
    State(state): State<RestState>,
    Path(project): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(denied) = require_admin(&state, &headers, &project).await {
        return denied;
    }
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

/// `POST /emulator/v1/projects/{project}/accounts/{uid}:revokeRefreshTokens`
/// — ends every session a user has, the way Firebase's
/// `revokeRefreshTokens(uid)` does.
///
/// Admin-gated: being able to sign anyone out is exactly as sensitive as
/// being able to sign them in.
pub async fn revoke_refresh_tokens(
    State(state): State<RestState>,
    Path((project, uid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(denied) = require_admin(&state, &headers, &project).await {
        return denied;
    }
    let uid = uid.trim_end_matches(":revokeRefreshTokens");
    match state.credentials.revoke_identity_tokens(&project, uid).await {
        Ok(()) => json_ok(serde_json::json!({ "localId": uid })),
        Err(status) => status_response(&status),
    }
}

/// `DELETE /emulator/v1/projects/{project}/databases/{db}/documents` —
/// clears all data (test-harness reset).
pub async fn clear_data(
    State(state): State<RestState>,
    Path((project, database)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(denied) = require_admin(&state, &headers, &project).await {
        return denied;
    }
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
    (http, [(header::CONTENT_TYPE, "application/json")], body.to_string()).into_response()
}

/// gRPC→HTTP status mapping (docs/architecture.md §11).
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
pub async fn cors(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let origin = request.headers().get(header::ORIGIN).cloned();
    let requested = request.headers().get(header::ACCESS_CONTROL_REQUEST_HEADERS).cloned();
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
        headers.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
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
