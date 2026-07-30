//! The Listen bidi stream: Firestore's realtime watch protocol.
//!
//! Contract (docs/architecture.md §3): echo client target ids exactly; per
//! target emit ADD → initial `DocumentChange`s → `CURRENT`, then the global
//! snapshot marker `TargetChange{NO_CHANGE, target_ids: [], read_time,
//! resume_token}` — the only thing that lets clients surface a snapshot.
//! Read times are strictly monotonic. Resume tokens are accepted by sending
//! `RESET` + full state (correct, if unoptimized). The server never
//! half-closes: streams end only when the client goes away.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Status, Streaming};
use waldflam_engine::path::{DatabaseName, ResourceName, ResourcePath};
use waldflam_engine::store::{Store, StoredDocument};
use waldflam_engine::watch::{CommitEvent, WatchHub};
use waldflam_proto::v1::target_change::TargetChangeType;
use waldflam_proto::v1::*;

use crate::service::{timestamp_from_us, to_wire_document};

enum TargetKind {
    Documents(Vec<ResourcePath>),
    Query { parent: ResourcePath, query: StructuredQuery },
}

struct TargetState {
    kind: TargetKind,
    /// Current members: document path → update_time_us.
    members: HashMap<String, i64>,
}

pub struct ListenSession {
    store: Store,
    database: Option<DatabaseName>,
    targets: HashMap<i32, TargetState>,
    next_server_target_id: i32,
    last_read_us: i64,
    out: mpsc::Sender<Result<ListenResponse, Status>>,
}

pub fn spawn(
    store: Store,
    hub: Arc<WatchHub>,
    mut requests: Streaming<ListenRequest>,
) -> ReceiverStream<Result<ListenResponse, Status>> {
    let (tx, rx) = mpsc::channel(256);
    let mut session = ListenSession {
        store,
        database: None,
        targets: HashMap::new(),
        next_server_target_id: 1_000_000,
        last_read_us: 0,
        out: tx,
    };
    tokio::spawn(async move {
        let mut events = hub.subscribe();
        loop {
            tokio::select! {
                request = requests.message() => match request {
                    Ok(Some(req)) => {
                        if let Err(end) = session.handle_request(req).await {
                            if let Some(status) = end {
                                let _ = session.out.send(Err(status)).await;
                            }
                            break;
                        }
                    }
                    // Client half-closed or dropped: end the stream.
                    Ok(None) | Err(_) => break,
                },
                event = events.recv() => match event {
                    Ok(event) => {
                        if session.handle_event(&event).await.is_err() {
                            break;
                        }
                    }
                    // Lagged: resync every target from scratch.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        if session.resync_all().await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
            }
        }
    });
    ReceiverStream::new(rx)
}

/// `Err(Some(status))` ends the stream with an error, `Err(None)` silently.
type Flow = Result<(), Option<Status>>;

impl ListenSession {
    fn read_time(&mut self, us: i64) -> i64 {
        self.last_read_us = us.max(self.last_read_us + 1);
        self.last_read_us
    }

    async fn send(&self, response: listen_response::ResponseType) -> Flow {
        self.out
            .send(Ok(ListenResponse { response_type: Some(response) }))
            .await
            .map_err(|_| None)
    }

    async fn send_target_change(
        &self,
        change_type: TargetChangeType,
        target_ids: Vec<i32>,
        read_us: Option<i64>,
        resume_token: Vec<u8>,
    ) -> Flow {
        self.send(listen_response::ResponseType::TargetChange(TargetChange {
            target_change_type: change_type as i32,
            target_ids,
            resume_token,
            read_time: read_us.map(timestamp_from_us),
            ..Default::default()
        }))
        .await
    }

    /// The global snapshot marker: empty target_ids + read_time.
    async fn send_snapshot_marker(&mut self, us: i64) -> Flow {
        let read_us = self.read_time(us);
        self.send_target_change(
            TargetChangeType::NoChange,
            Vec::new(),
            Some(read_us),
            read_us.to_be_bytes().to_vec(),
        )
        .await
    }

    async fn handle_request(&mut self, req: ListenRequest) -> Flow {
        let database = DatabaseName::parse(&req.database)
            .map_err(|e| Some(Status::invalid_argument(e.to_string())))?;
        match self.database.as_ref() {
            None => self.database = Some(database),
            Some(existing) if *existing != database => {
                return Err(Some(Status::invalid_argument(
                    "listen stream spans databases",
                )));
            }
            Some(_) => {}
        }
        match req.target_change {
            Some(listen_request::TargetChange::AddTarget(target)) => {
                self.add_target(target).await
            }
            Some(listen_request::TargetChange::RemoveTarget(id)) => {
                self.targets.remove(&id);
                Ok(())
            }
            None => Ok(()),
        }
    }

    async fn add_target(&mut self, target: Target) -> Flow {
        let id = if target.target_id != 0 {
            target.target_id
        } else {
            self.next_server_target_id += 1;
            self.next_server_target_id
        };
        if self.targets.contains_key(&id) {
            return Err(Some(Status::invalid_argument("duplicate target id")));
        }

        let kind = match target.target_type {
            Some(target::TargetType::Documents(d)) => {
                let mut paths = Vec::new();
                for name in &d.documents {
                    let parsed = ResourceName::parse_document(name)
                        .map_err(|e| Some(Status::invalid_argument(e.to_string())))?;
                    paths.push(parsed.path);
                }
                TargetKind::Documents(paths)
            }
            Some(target::TargetType::Query(q)) => {
                let parent = ResourceName::parse(&q.parent)
                    .map_err(|e| Some(Status::invalid_argument(e.to_string())))?;
                let Some(target::query_target::QueryType::StructuredQuery(query)) = q.query_type
                else {
                    return Err(Some(Status::invalid_argument("missing structured_query")));
                };
                TargetKind::Query { parent: parent.path, query }
            }
            None => return Err(Some(Status::invalid_argument("missing target type"))),
        };

        // Resuming: we don't replay deltas — RESET tells the client to drop
        // its state, then we send the full current state.
        if target.resume_type.is_some() {
            self.send_target_change(TargetChangeType::Reset, vec![id], None, Vec::new())
                .await?;
        }

        self.send_target_change(TargetChangeType::Add, vec![id], None, Vec::new())
            .await?;

        let state = TargetState { kind, members: HashMap::new() };
        self.targets.insert(id, state);
        self.send_initial_state(id).await
    }

    /// Full state for one target: doc changes/deletes, CURRENT, snapshot.
    async fn send_initial_state(&mut self, id: i32) -> Flow {
        let database = self.database.clone().expect("database set");
        let state = self.targets.get(&id).expect("just inserted");
        let mut found = Vec::new();
        let mut missing = Vec::new();
        match &state.kind {
            TargetKind::Documents(paths) => {
                for path in paths {
                    match self.store.get_document(&database, path).await {
                        Ok(Some(doc)) => found.push(doc),
                        Ok(None) => missing.push(path.clone()),
                        Err(e) => return Err(Some(Status::internal(e.to_string()))),
                    }
                }
            }
            TargetKind::Query { parent, query } => {
                match waldflam_engine::query::run_query(&self.store, &database, parent, query)
                    .await
                {
                    Ok(docs) => found = docs,
                    Err(e) => return Err(Some(Status::invalid_argument(e.to_string()))),
                }
            }
        }

        let now = crate::service::now_us();
        let mut members = HashMap::new();
        for doc in found {
            members.insert(doc.path.to_string(), doc.update_time_us);
            self.send_document_change(&database, doc, id).await?;
        }
        let read_us = self.read_time(now);
        for path in missing {
            self.send(listen_response::ResponseType::DocumentDelete(DocumentDelete {
                document: full_name(&database, &path),
                removed_target_ids: vec![id],
                read_time: Some(timestamp_from_us(read_us)),
            }))
            .await?;
        }
        self.targets.get_mut(&id).expect("present").members = members;

        self.send_target_change(TargetChangeType::Current, vec![id], Some(read_us), Vec::new())
            .await?;
        self.send_snapshot_marker(now).await
    }

    async fn send_document_change(
        &self,
        database: &DatabaseName,
        doc: StoredDocument,
        id: i32,
    ) -> Flow {
        let name = ResourceName { database: database.clone(), path: doc.path.clone() };
        self.send(listen_response::ResponseType::DocumentChange(DocumentChange {
            document: Some(to_wire_document(&name, doc)),
            target_ids: vec![id],
            ..Default::default()
        }))
        .await
    }

    async fn handle_event(&mut self, event: &CommitEvent) -> Flow {
        if self.database.as_ref() != Some(&event.database) {
            return Ok(());
        }
        let database = event.database.clone();
        let mut any_change = false;
        let target_ids: Vec<i32> = self.targets.keys().copied().collect();
        for id in target_ids {
            let state = self.targets.get(&id).expect("iterating");
            match &state.kind {
                TargetKind::Documents(paths) => {
                    let watched: Vec<(ResourcePath, Option<StoredDocument>)> = event
                        .changes
                        .iter()
                        .filter(|(p, _)| paths.contains(p))
                        .cloned()
                        .collect();
                    for (path, new_state) in watched {
                        any_change = true;
                        match new_state {
                            Some(doc) => {
                                self.targets
                                    .get_mut(&id)
                                    .expect("present")
                                    .members
                                    .insert(path.to_string(), doc.update_time_us);
                                self.send_document_change(&database, doc, id).await?;
                            }
                            None => {
                                self.targets
                                    .get_mut(&id)
                                    .expect("present")
                                    .members
                                    .remove(&path.to_string());
                                let read_us = self.read_time(event.commit_us);
                                self.send(listen_response::ResponseType::DocumentDelete(
                                    DocumentDelete {
                                        document: full_name(&database, &path),
                                        removed_target_ids: vec![id],
                                        read_time: Some(timestamp_from_us(read_us)),
                                    },
                                ))
                                .await?;
                            }
                        }
                    }
                }
                TargetKind::Query { parent, query } => {
                    if !event
                        .changes
                        .iter()
                        .any(|(p, _)| query_may_cover(parent, query, p))
                    {
                        continue;
                    }
                    // Re-run and diff against tracked membership (handles
                    // limits/cursors pulling docs into or out of the window).
                    let docs = match waldflam_engine::query::run_query(
                        &self.store,
                        &database,
                        parent,
                        query,
                    )
                    .await
                    {
                        Ok(docs) => docs,
                        Err(e) => return Err(Some(Status::internal(e.to_string()))),
                    };
                    let mut new_members = HashMap::new();
                    let mut entered_or_updated = Vec::new();
                    for doc in docs {
                        let key = doc.path.to_string();
                        let previous = state.members.get(&key);
                        if previous != Some(&doc.update_time_us) {
                            entered_or_updated.push(doc.clone());
                        }
                        new_members.insert(key, doc.update_time_us);
                    }
                    let departed: Vec<String> = state
                        .members
                        .keys()
                        .filter(|k| !new_members.contains_key(*k))
                        .cloned()
                        .collect();

                    if entered_or_updated.is_empty() && departed.is_empty() {
                        continue;
                    }
                    any_change = true;
                    self.targets.get_mut(&id).expect("present").members = new_members;
                    for doc in entered_or_updated {
                        self.send_document_change(&database, doc, id).await?;
                    }
                    let read_us = self.read_time(event.commit_us);
                    for path in departed {
                        self.send(listen_response::ResponseType::DocumentRemove(DocumentRemove {
                            document: format!("{}/{}", database.documents_root(), path),
                            removed_target_ids: vec![id],
                            read_time: Some(timestamp_from_us(read_us)),
                        }))
                        .await?;
                    }
                }
            }
        }
        if any_change {
            self.send_snapshot_marker(event.commit_us).await?;
        }
        Ok(())
    }

    async fn resync_all(&mut self) -> Flow {
        let ids: Vec<i32> = self.targets.keys().copied().collect();
        for id in ids {
            self.send_target_change(TargetChangeType::Reset, vec![id], None, Vec::new())
                .await?;
            if let Some(state) = self.targets.get_mut(&id) {
                state.members.clear();
            }
            self.send_initial_state(id).await?;
        }
        Ok(())
    }
}

/// Cheap pre-filter: could a change at `path` affect this query target?
fn query_may_cover(parent: &ResourcePath, query: &StructuredQuery, path: &ResourcePath) -> bool {
    let Some(selector) = query.from.first() else { return false };
    let Some(collection) = path.parent() else { return false };
    if selector.all_descendants {
        collection.last_id() == Some(selector.collection_id.as_str())
    } else {
        match parent.child(&selector.collection_id) {
            Ok(target_collection) => collection == target_collection,
            Err(_) => false,
        }
    }
}

fn full_name(database: &DatabaseName, path: &ResourcePath) -> String {
    format!("{}/{}", database.documents_root(), path)
}
