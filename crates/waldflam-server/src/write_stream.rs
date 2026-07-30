//! The bidi Write stream, generic over the request source so both native
//! gRPC and the WebChannel bridge can drive it.
//!
//! Contract: every response carries a non-empty `stream_token`; the
//! handshake (and any empty-writes request) gets a token-only response with
//! no `write_results`; `stream_id` is never required.

use std::sync::Arc;

use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::Status;
use waldflam_engine::path::DatabaseName;
use waldflam_engine::store::Store;
use waldflam_engine::txn::TransactionManager;
use waldflam_engine::watch::WatchHub;
use waldflam_proto::v1::{WriteRequest, WriteResponse, WriteResult};

use crate::service::{engine_status, now_us, timestamp_from_us};

pub fn spawn<S>(
    store: Store,
    hub: Arc<WatchHub>,
    txns: Arc<TransactionManager>,
    auth: crate::auth::Authorization,
    rules: Arc<crate::rules::RulesRegistry>,
    mut requests: S,
) -> ReceiverStream<Result<WriteResponse, Status>>
where
    S: Stream<Item = Result<WriteRequest, Status>> + Send + Unpin + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<WriteResponse, Status>>(64);
    tokio::spawn(async move {
        let mut token: u64 = 0;
        let mut database: Option<DatabaseName> = None;
        while let Some(Ok(req)) = requests.next().await {
            if database.is_none() {
                match DatabaseName::parse(&req.database) {
                    Ok(db) => database = Some(db),
                    Err(e) => {
                        let _ = tx.send(Err(Status::invalid_argument(e.to_string()))).await;
                        return;
                    }
                }
            }
            let db = database.clone().expect("just set");
            token += 1;
            let stream_token = token.to_be_bytes().to_vec();

            if req.writes.is_empty() {
                let ok = tx.send(Ok(WriteResponse { stream_token, ..Default::default() })).await;
                if ok.is_err() {
                    return;
                }
                continue;
            }

            if let Err(status) =
                crate::rules::check_writes(&rules, &store, &auth, &db, &req.writes).await
            {
                let _ = tx.send(Err(status)).await;
                return;
            }

            let now = now_us();
            let guard = txns.commit_lock.lock().await;
            let applied =
                waldflam_engine::commit::apply_commit(&store, &db, &req.writes, now).await;
            drop(guard);
            match applied {
                Ok(applied) => {
                    hub.publish(waldflam_engine::watch::CommitEvent {
                        database: db,
                        changes: applied.changes,
                        commit_us: now,
                    });
                    let response = WriteResponse {
                        stream_token,
                        write_results: applied
                            .outcomes
                            .into_iter()
                            .map(|o| WriteResult {
                                update_time: Some(timestamp_from_us(o.update_time_us)),
                                transform_results: o.transform_results,
                            })
                            .collect(),
                        commit_time: Some(timestamp_from_us(now)),
                        ..Default::default()
                    };
                    if tx.send(Ok(response)).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(engine_status(e))).await;
                    return;
                }
            }
        }
    });
    ReceiverStream::new(rx)
}
