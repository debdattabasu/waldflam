//! WebChannel (BrowserChannel wire v8) — the browser JS SDK's streaming
//! transport for Listen/Write. Server behavior derived from closure-library's
//! client implementation (Apache-2.0); the wire contract is in §3.
//!
//! Endpoint: `{GET,POST} /google.firestore.v1.Firestore/{Listen|Write}/channel`
//! - handshake POST (no SID): create session, reply `X-HTTP-Session-Id`
//!   header + framed `[[0,["c",sid,null,8]]]`, feed bundled first messages
//! - backchannel GET (`RID=rpc`): long-lived chunked frames
//!   `<len>\n[[id,[obj]]]`, immediate first frame (buffering-proxy
//!   detection), `noop` keepalives, strictly increasing array ids, resume
//!   from `AID`
//! - forward POST (SID set): decode `count/ofs/req{i}___data__` form body,
//!   reply flat `[1, lastArrayId, 0]`
//! - `TYPE=terminate`: drop the session
//!
//! Framing lengths count UTF-16 code units of *decoded* text, so all JSON
//! is emitted ASCII-only (`\uXXXX`-escaped) making length == byte count.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use prost::Message;
use tokio::sync::{Notify, mpsc};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use waldflam_proto::v1::{ListenRequest, WriteRequest};

use crate::rest::RestState;

const NOOP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(25);

#[derive(Default)]
pub struct WebChannelSessions {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    counter: AtomicU64,
}

enum ForwardSender {
    Listen(mpsc::Sender<Result<ListenRequest, Status>>),
    Write(mpsc::Sender<Result<WriteRequest, Status>>),
}

struct Session {
    forward: ForwardSender,
    inner: Mutex<SessionInner>,
    notify: Notify,
}

struct SessionInner {
    /// Unacknowledged data frames: (array id, inner JSON payload — the
    /// `[<object>]` part of `[[id,[<object>]]]`).
    arrays: VecDeque<(u64, String)>,
    next_array_id: u64,
    /// Highest data array id allocated (for forward-POST status replies).
    last_data_array_id: u64,
    seen_rids: HashSet<String>,
    terminated: bool,
}

impl Session {
    fn push_array(&self, payload: String) {
        let mut inner = self.inner.lock().expect("session lock");
        let id = inner.next_array_id;
        inner.next_array_id += 1;
        inner.last_data_array_id = id;
        inner.arrays.push_back((id, payload));
        drop(inner);
        self.notify.notify_waiters();
    }

    fn alloc_control_id(&self) -> u64 {
        let mut inner = self.inner.lock().expect("session lock");
        let id = inner.next_array_id;
        inner.next_array_id += 1;
        id
    }

    fn ack(&self, aid: u64) {
        let mut inner = self.inner.lock().expect("session lock");
        inner.arrays.retain(|(id, _)| *id > aid);
    }
}

/// Escapes non-ASCII as `\uXXXX` (valid JSON only holds non-ASCII inside
/// strings, so a global char-level escape is safe) — makes frame lengths
/// unambiguous.
fn ascii_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

/// `<len>\n<payload>` — payload must already be ASCII-only.
fn frame(payload: &str) -> String {
    format!("{}\n{}", payload.len(), payload)
}

fn query_map(raw: &Option<String>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(raw) = raw {
        for (k, v) in form_urlencoded::parse(raw.as_bytes()) {
            map.insert(k.into_owned(), v.into_owned());
        }
    }
    map
}

/// Middleware: intercepts `/google.firestore.v1.Firestore/{rpc}/channel`
/// before the gRPC router's wildcard claims it.
pub async fn intercept(
    State(state): State<RestState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path();
    let rpc = path
        .strip_prefix("/google.firestore.v1.Firestore/")
        .and_then(|rest| rest.strip_suffix("/channel"))
        .map(str::to_owned);
    let Some(rpc) = rpc else {
        return next.run(request).await;
    };
    let raw_query = request.uri().query().map(str::to_owned);
    let body = axum::body::to_bytes(request.into_body(), 1 << 22)
        .await
        .unwrap_or_default();
    handle(state, rpc, raw_query, body).await
}

async fn handle(state: RestState, rpc: String, raw_query: Option<String>, body: Bytes) -> Response {
    let params = query_map(&raw_query);
    let sessions = state.sessions.clone();

    if params.get("TYPE").map(String::as_str) == Some("terminate") {
        if let Some(sid) = params.get("SID") {
            sessions.sessions.lock().expect("sessions lock").remove(sid);
        }
        return StatusCode::NO_CONTENT.into_response();
    }

    if params.get("RID").map(String::as_str) == Some("rpc") {
        return backchannel(state, params).await;
    }

    match params.get("SID") {
        None => handshake(state, &rpc, &params, &body).await,
        Some(sid) => forward_post(state, sid.clone(), &params, &body).await,
    }
}

fn framed_response(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

fn unknown_sid() -> Response {
    // The client's check is `indexOf('Unknown SID') > 0` — the phrase must
    // not be at position zero.
    (StatusCode::BAD_REQUEST, "Error: Unknown SID").into_response()
}

/// Extracts credentials from the handshake body's `headers=` block:
/// an HTTP/1.1-style CRLF-separated header list, URL-encoded whole.
fn auth_from_body(body: &[u8]) -> crate::auth::Authorization {
    let fields: HashMap<String, String> = form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let Some(block) = fields.get("headers") else {
        return crate::auth::Authorization::Unauthenticated;
    };
    let header = block.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("authorization")
            .then(|| value.trim().to_owned())
    });
    crate::auth::Authorization::from_header(header.as_deref())
        .unwrap_or(crate::auth::Authorization::Unauthenticated)
}

/// Decodes the `count`/`ofs`/`req{i}___data__` form body into raw JSON
/// message strings, in order.
fn decode_forward_body(body: &[u8]) -> Vec<String> {
    let fields: HashMap<String, String> = form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let count: usize = fields
        .get("count")
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (0..count)
        .filter_map(|i| fields.get(&format!("req{i}___data__")).cloned())
        .collect()
}

async fn deliver(state: &RestState, session: &Session, messages: Vec<String>) -> Result<(), Status> {
    for json in messages {
        match &session.forward {
            ForwardSender::Listen(tx) => {
                let req: ListenRequest =
                    crate::rest::json_to_message(state, "google.firestore.v1.ListenRequest", json.as_bytes())?;
                tx.send(Ok(req)).await.map_err(|_| Status::cancelled("stream ended"))?;
            }
            ForwardSender::Write(tx) => {
                let req: WriteRequest =
                    crate::rest::json_to_message(state, "google.firestore.v1.WriteRequest", json.as_bytes())?;
                tx.send(Ok(req)).await.map_err(|_| Status::cancelled("stream ended"))?;
            }
        }
    }
    Ok(())
}

async fn handshake(
    state: RestState,
    rpc: &str,
    params: &HashMap<String, String>,
    body: &[u8],
) -> Response {
    let auth = auth_from_body(body);
    let sid = format!(
        "wf{}-{:x}",
        state.sessions.counter.fetch_add(1, Ordering::Relaxed),
        crate::service::now_us()
    );

    // Spawn the underlying RPC with an mpsc-fed request stream and pump its
    // responses into the session's array buffer as JSON.
    let (session, mut responses): (Arc<Session>, mpsc::Receiver<Result<String, Status>>) =
        match rpc {
            "Listen" => {
                let (tx, rx) = mpsc::channel(64);
                let stream = crate::listen::spawn(
                    state.svc.store_handle(),
                    state.svc.hub_handle(),
                    auth.clone(),
                    state.svc.rules.clone(),
                    ReceiverStream::new(rx),
                );
                let (jtx, jrx) = mpsc::channel(64);
                pump_json(state.clone(), "google.firestore.v1.ListenResponse", stream, jtx);
                (make_session(ForwardSender::Listen(tx)), jrx)
            }
            "Write" => {
                let (tx, rx) = mpsc::channel(64);
                let stream = crate::write_stream::spawn(
                    state.svc.store_handle(),
                    state.svc.hub_handle(),
                    state.svc.txns_handle(),
                    auth.clone(),
                    state.svc.rules.clone(),
                    ReceiverStream::new(rx),
                );
                let (jtx, jrx) = mpsc::channel(64);
                pump_json(state.clone(), "google.firestore.v1.WriteResponse", stream, jtx);
                (make_session(ForwardSender::Write(tx)), jrx)
            }
            _ => return (StatusCode::NOT_FOUND, "unknown rpc").into_response(),
        };

    state
        .sessions
        .sessions
        .lock()
        .expect("sessions lock")
        .insert(sid.clone(), session.clone());

    // Buffer-filler task: RPC responses (and terminal errors, delivered
    // in-band as {"error": …}) become data arrays.
    {
        let session = session.clone();
        tokio::spawn(async move {
            while let Some(item) = responses.recv().await {
                match item {
                    Ok(json) => session.push_array(format!("[{}]", ascii_json(&json))),
                    Err(status) => {
                        let err = serde_json::json!({
                            "error": {
                                "status": code_name(status.code()),
                                "message": status.message(),
                            }
                        });
                        session.push_array(format!("[{}]", ascii_json(&err.to_string())));
                        break;
                    }
                }
            }
        });
    }

    // Feed the messages bundled into the handshake.
    let messages = decode_forward_body(body);
    if let Err(status) = deliver(&state, &session, messages).await {
        return crate::rest::status_response(&status);
    }

    let payload = format!("[[0,[\"c\",{},null,8]]]", serde_json::json!(sid));
    let _ = params; // VER/RID/database validated implicitly by message decode
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-http-session-id", &sid)
        .body(Body::from(frame(&payload)))
        .expect("response build")
}

fn make_session(forward: ForwardSender) -> Arc<Session> {
    Arc::new(Session {
        forward,
        inner: Mutex::new(SessionInner {
            arrays: VecDeque::new(),
            next_array_id: 1,
            last_data_array_id: 0,
            seen_rids: HashSet::new(),
            terminated: false,
        }),
        notify: Notify::new(),
    })
}

/// Pumps typed RPC responses into JSON strings.
fn pump_json<T>(
    state: RestState,
    message_name: &'static str,
    mut stream: ReceiverStream<Result<T, Status>>,
    out: mpsc::Sender<Result<String, Status>>,
) where
    T: Message + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(item) = stream.next().await {
            let mapped = match item {
                Ok(msg) => crate::rest::message_to_json(&state, message_name, &msg),
                Err(status) => Err(status),
            };
            if out.send(mapped).await.is_err() {
                return;
            }
        }
    });
}

async fn forward_post(
    state: RestState,
    sid: String,
    params: &HashMap<String, String>,
    body: &[u8],
) -> Response {
    let Some(session) = state
        .sessions
        .sessions
        .lock()
        .expect("sessions lock")
        .get(&sid)
        .cloned()
    else {
        return unknown_sid();
    };
    if let Some(aid) = params.get("AID").and_then(|a| a.parse::<u64>().ok()) {
        session.ack(aid);
    }

    // Dedupe retransmissions by RID.
    let is_new = match params.get("RID") {
        Some(rid) => session
            .inner
            .lock()
            .expect("session lock")
            .seen_rids
            .insert(rid.clone()),
        None => true,
    };
    if is_new {
        let messages = decode_forward_body(body);
        if let Err(status) = deliver(&state, &session, messages).await {
            return crate::rest::status_response(&status);
        }
    }

    let last = session
        .inner
        .lock()
        .expect("session lock")
        .last_data_array_id;
    framed_response(frame(&format!("[1,{last},0]")))
}

async fn backchannel(state: RestState, params: HashMap<String, String>) -> Response {
    let Some(session) = params
        .get("SID")
        .and_then(|sid| {
            state
                .sessions
                .sessions
                .lock()
                .expect("sessions lock")
                .get(sid)
                .cloned()
        })
    else {
        return unknown_sid();
    };
    if let Some(aid) = params.get("AID").and_then(|a| a.parse::<u64>().ok()) {
        session.ack(aid);
    }
    let long_polling = params.get("CI").map(String::as_str) == Some("1");
    let hold_ms: u64 = params
        .get("TO")
        .and_then(|t| t.parse().ok())
        .unwrap_or(30_000);

    let (tx, rx) = mpsc::channel::<Result<Bytes, std::convert::Infallible>>(32);
    tokio::spawn(async move {
        // Cursor over the session buffer: deliver everything unacked, then
        // follow live pushes. First frame goes out immediately (buffering-
        // proxy detection).
        let mut cursor = 0u64;
        let noop = |s: &Session| format!("[[{},[\"noop\"]]]", s.alloc_control_id());
        if tx.send(Ok(Bytes::from(frame(&noop(&session))))).await.is_err() {
            return;
        }
        let started = std::time::Instant::now();
        loop {
            let pending: Vec<(u64, String)> = {
                let inner = session.inner.lock().expect("session lock");
                if inner.terminated {
                    return;
                }
                inner
                    .arrays
                    .iter()
                    .filter(|(id, _)| *id > cursor)
                    .cloned()
                    .collect()
            };
            if !pending.is_empty() {
                let mut out = String::new();
                for (id, payload) in &pending {
                    cursor = *id;
                    out.push_str(&frame(&format!("[[{id},{payload}]]")));
                }
                if tx.send(Ok(Bytes::from(out))).await.is_err() {
                    return;
                }
                if long_polling {
                    return; // complete the GET; client re-polls
                }
                continue;
            }
            if long_polling && started.elapsed() >= std::time::Duration::from_millis(hold_ms) {
                return; // at least the initial noop was sent
            }
            let wait = tokio::time::timeout(NOOP_INTERVAL, session.notify.notified()).await;
            if wait.is_err() {
                // Keepalive.
                if tx.send(Ok(Bytes::from(frame(&noop(&session))))).await.is_err() {
                    return;
                }
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(ReceiverStream::new(rx)))
        .expect("response build")
}

fn code_name(code: tonic::Code) -> &'static str {
    use tonic::Code::*;
    match code {
        Ok => "OK",
        Cancelled => "CANCELLED",
        Unknown => "UNKNOWN",
        InvalidArgument => "INVALID_ARGUMENT",
        DeadlineExceeded => "DEADLINE_EXCEEDED",
        NotFound => "NOT_FOUND",
        AlreadyExists => "ALREADY_EXISTS",
        PermissionDenied => "PERMISSION_DENIED",
        ResourceExhausted => "RESOURCE_EXHAUSTED",
        FailedPrecondition => "FAILED_PRECONDITION",
        Aborted => "ABORTED",
        OutOfRange => "OUT_OF_RANGE",
        Unimplemented => "UNIMPLEMENTED",
        Internal => "INTERNAL",
        Unavailable => "UNAVAILABLE",
        DataLoss => "DATA_LOSS",
        Unauthenticated => "UNAUTHENTICATED",
    }
}
