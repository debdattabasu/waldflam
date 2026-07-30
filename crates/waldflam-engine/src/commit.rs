//! The Commit write path: preconditions, update masks, field transforms.
//!
//! Semantics follow docs/architecture.md §3/§11: precondition failures use
//! the exact codes clients act on; `increment` saturates on int64 overflow;
//! `maximum`/`minimum` are NaN-aware; array union/remove use index-value
//! equality (so `1` deduplicates against `1.0`); all `serverTimestamp`s in
//! one commit share the request time.
//!
//! The whole commit — the reads that preconditions are checked against and
//! every resulting write — runs inside one MongoDB transaction, so a batch
//! either lands completely or not at all, and a concurrent writer touching
//! the same document forces a restart instead of a lost update.

use std::collections::HashMap;

use mongodb::error::{TRANSIENT_TRANSACTION_ERROR, UNKNOWN_TRANSACTION_COMMIT_RESULT};
use mongodb::options::WriteConcern;
use waldflam_proto::v1::document_transform::FieldTransform;
use waldflam_proto::v1::document_transform::field_transform::TransformType;
use waldflam_proto::v1::precondition::ConditionType;
use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::write::Operation;
use waldflam_proto::v1::{ArrayValue, Value, Write};

use crate::EngineError;
use crate::fields::{delete_field, get_field, set_field};
use crate::index_key::encode_value;
use crate::order::compare_values;
use crate::path::{DatabaseName, ResourceName, ResourcePath};
use crate::store::Store;

/// Per-write outcome for `CommitResponse.write_results`.
#[derive(Debug)]
pub struct WriteOutcome {
    pub update_time_us: i64,
    pub transform_results: Vec<Value>,
}

/// A commit's results plus the final state of every changed document
/// (`None` = deleted), for watch fan-out.
#[derive(Debug)]
pub struct CommitApplied {
    pub outcomes: Vec<WriteOutcome>,
    pub changes: Vec<crate::watch::DocumentDelta>,
}

#[derive(Debug, Clone)]
struct DocState {
    /// (create_time_us, update_time_us, fields) when the doc exists.
    current: Option<(i64, i64, HashMap<String, Value>)>,
    /// State as loaded, for trigger before-images.
    before: Option<crate::store::StoredDocument>,
    dirty: bool,
}

/// Restarts allowed when MongoDB reports a transient transaction error — a
/// write conflict with a concurrent commit on the same document. Exhausting
/// them is reported as contention, which is what clients retry on.
const MAX_TRANSACTION_ATTEMPTS: u32 = 10;

/// Bounds the commit-only retry taken when the transaction's outcome is
/// unknown (the server may already have committed).
const MAX_COMMIT_ATTEMPTS: u32 = 3;

/// Applies a `Commit`'s writes atomically: preconditions are checked against
/// the evolving in-memory state, and the reads behind them plus every
/// resulting write share one MongoDB transaction.
pub async fn apply_commit(
    store: &Store,
    database: &DatabaseName,
    writes: &[Write],
    now_us: i64,
) -> Result<CommitApplied, EngineError> {
    let mut session = store.start_session().await?;
    for attempt in 0..MAX_TRANSACTION_ATTEMPTS {
        session.start_transaction().write_concern(WriteConcern::majority()).await?;
        let applied =
            match apply_in_transaction(store, &mut session, database, writes, now_us).await {
                Ok(applied) => applied,
                Err(error) => {
                    // Best effort: an un-aborted transaction expires server-side.
                    let _ = session.abort_transaction().await;
                    if is_transient(&error) {
                        backoff(attempt).await;
                        continue;
                    }
                    return Err(error);
                }
            };
        match commit_transaction(&mut session).await {
            Ok(()) => return Ok(applied),
            Err(error) if is_transient(&error) => backoff(attempt).await,
            Err(error) => return Err(error),
        }
    }
    Err(EngineError::Aborted)
}

/// Spreads out contenders before restarting a conflicted transaction.
/// Without it, writers racing on one document collide repeatedly: each
/// restarts the instant it loses, straight into the others doing the same.
/// Full jitter over an exponentially growing window, seeded from the clock
/// so concurrent tasks land on different delays without pulling in an RNG.
async fn backoff(attempt: u32) {
    let ceiling_ms = 2u64 << attempt.min(6); // 2ms … 128ms
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.subsec_nanos() as u64)
        .unwrap_or(0);
    tokio::time::sleep(std::time::Duration::from_millis(jitter % ceiling_ms)).await;
}

/// One attempt: everything here runs against `session`'s transaction and is
/// discarded wholesale if it aborts.
async fn apply_in_transaction(
    store: &Store,
    session: &mut mongodb::ClientSession,
    database: &DatabaseName,
    writes: &[Write],
    now_us: i64,
) -> Result<CommitApplied, EngineError> {
    // Load each distinct target once.
    let mut states: HashMap<String, DocState> = HashMap::new();
    for write in writes {
        let path = write_target(database, write)?;
        let key = path.to_string();
        if let std::collections::hash_map::Entry::Vacant(e) = states.entry(key) {
            let loaded = store.get_document_in_session(session, database, &path).await?;
            let current =
                loaded.as_ref().map(|d| (d.create_time_us, d.update_time_us, d.fields.clone()));
            e.insert(DocState { current, before: loaded, dirty: false });
        }
    }

    // Apply writes in order against the in-memory view.
    let mut outcomes = Vec::with_capacity(writes.len());
    for write in writes {
        let path = write_target(database, write)?;
        let state = states.get_mut(&path.to_string()).expect("preloaded");
        outcomes.push(apply_write(write, &path, state, now_us)?);
    }

    // Persist final states.
    let mut changes = Vec::new();
    for write in writes {
        let path = write_target(database, write)?;
        let key = path.to_string();
        let state = states.get_mut(&key).expect("preloaded");
        if !state.dirty {
            continue;
        }
        state.dirty = false;
        let before = state.before.clone();
        match &state.current {
            Some((_, _, fields)) => {
                let stored = store
                    .set_document_in_session(session, database, &path, fields.clone(), now_us)
                    .await?;
                changes.push(crate::watch::DocumentDelta { path, before, after: Some(stored) });
            }
            None => {
                store.delete_document_in_session(session, database, &path).await?;
                changes.push(crate::watch::DocumentDelta { path, before, after: None });
            }
        }
    }

    // Publish inside the transaction: other instances learn about the commit
    // exactly when its writes become visible, and never if it rolls back.
    if !changes.is_empty() {
        let paths = changes.iter().map(|delta| delta.path.to_string()).collect();
        store.append_commit_notice_in_session(session, database, now_us, paths).await?;
    }
    Ok(CommitApplied { outcomes, changes })
}

/// Commits, retrying the commit alone while its outcome is unknown — a blip
/// after the server may already have applied it. Retrying is safe: MongoDB
/// treats a repeat commit of an already-committed transaction as a no-op.
async fn commit_transaction(session: &mut mongodb::ClientSession) -> Result<(), EngineError> {
    let mut last = None;
    for _ in 0..MAX_COMMIT_ATTEMPTS {
        match session.commit_transaction().await {
            Ok(()) => return Ok(()),
            Err(error) if error.contains_label(UNKNOWN_TRANSACTION_COMMIT_RESULT) => {
                last = Some(error);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(last.map(EngineError::from).unwrap_or(EngineError::Aborted))
}

/// A write conflict with a concurrent commit: MongoDB labels these
/// retryable, and re-running the whole transaction is the prescribed fix.
fn is_transient(error: &EngineError) -> bool {
    matches!(error, EngineError::Mongo(e) if e.contains_label(TRANSIENT_TRANSACTION_ERROR))
}

fn write_target(database: &DatabaseName, write: &Write) -> Result<ResourcePath, EngineError> {
    let name = match write.operation.as_ref() {
        Some(Operation::Update(doc)) => &doc.name,
        Some(Operation::Delete(name)) | Some(Operation::Verify(name)) => name,
        Some(Operation::Transform(t)) => &t.document,
        None => {
            return Err(EngineError::InvalidArgument("write has no operation".into()));
        }
    };
    let parsed = ResourceName::parse_document(name)?;
    if parsed.database != *database {
        return Err(EngineError::InvalidArgument(format!(
            "write targets foreign database: {name:?}"
        )));
    }
    Ok(parsed.path)
}

fn apply_write(
    write: &Write,
    path: &ResourcePath,
    state: &mut DocState,
    now_us: i64,
) -> Result<WriteOutcome, EngineError> {
    check_precondition(write, path, state)?;

    let mut transform_results = Vec::new();
    match write.operation.as_ref().expect("validated") {
        Operation::Update(doc) => {
            match write.update_mask.as_ref() {
                None => {
                    // Full set: replace the document's fields entirely.
                    let create = state.current.as_ref().map(|(c, ..)| *c).unwrap_or(now_us);
                    state.current = Some((create, now_us, doc.fields.clone()));
                }
                Some(mask) => {
                    // Merge: each mask path is set from the update document,
                    // or deleted when absent there.
                    let (create, fields) = match state.current.take() {
                        Some((c, _, f)) => (c, f),
                        None => (now_us, HashMap::new()),
                    };
                    let mut fields = fields;
                    for field_path in &mask.field_paths {
                        match get_field(&doc.fields, field_path) {
                            Some(v) => set_field(&mut fields, field_path, v.clone()),
                            None => delete_field(&mut fields, field_path),
                        }
                    }
                    state.current = Some((create, now_us, fields));
                }
            }
            for transform in &write.update_transforms {
                transform_results.push(apply_transform(state, transform, now_us)?);
            }
            state.dirty = true;
        }
        Operation::Delete(_) => {
            state.current = None;
            state.dirty = true;
        }
        Operation::Verify(_) => {}
        Operation::Transform(t) => {
            if state.current.is_none() {
                state.current = Some((now_us, now_us, HashMap::new()));
            }
            for transform in &t.field_transforms {
                transform_results.push(apply_transform(state, transform, now_us)?);
            }
            state.dirty = true;
        }
    }
    if let Some((_, update, _)) = state.current.as_mut() {
        *update = now_us;
    }
    Ok(WriteOutcome { update_time_us: now_us, transform_results })
}

fn check_precondition(
    write: &Write,
    path: &ResourcePath,
    state: &DocState,
) -> Result<(), EngineError> {
    let Some(precondition) = write.current_document.as_ref() else {
        return Ok(());
    };
    let exists = state.current.is_some();
    match precondition.condition_type.as_ref() {
        Some(ConditionType::Exists(true)) if !exists => {
            Err(EngineError::NotFound(format!("no document to update: {path}")))
        }
        Some(ConditionType::Exists(false)) if exists => {
            Err(EngineError::AlreadyExists(format!("document already exists: {path}")))
        }
        Some(ConditionType::UpdateTime(ts)) => {
            let expected = ts.seconds * 1_000_000 + i64::from(ts.nanos) / 1_000;
            match &state.current {
                Some((_, update_us, _)) if *update_us == expected => Ok(()),
                Some(_) => Err(EngineError::FailedPrecondition(format!(
                    "stored version does not match the given base version: {path}"
                ))),
                None => Err(EngineError::NotFound(format!("no document to update: {path}"))),
            }
        }
        _ => Ok(()),
    }
}

fn apply_transform(
    state: &mut DocState,
    transform: &FieldTransform,
    now_us: i64,
) -> Result<Value, EngineError> {
    let (_, _, fields) = state.current.as_mut().expect("transform target exists");
    let current = get_field(fields, &transform.field_path).cloned();
    let (result, stored): (Value, Option<Value>) = match transform.transform_type.as_ref() {
        Some(TransformType::SetToServerValue(_)) => {
            let ts = Value {
                value_type: Some(ValueType::TimestampValue(prost_types::Timestamp {
                    seconds: now_us.div_euclid(1_000_000),
                    nanos: (now_us.rem_euclid(1_000_000) * 1_000) as i32,
                })),
            };
            (ts.clone(), Some(ts))
        }
        Some(TransformType::Increment(operand)) => {
            let v = increment(current.as_ref(), operand)?;
            (v.clone(), Some(v))
        }
        Some(TransformType::Maximum(operand)) => {
            let v = max_min(current.as_ref(), operand, true)?;
            (v.clone(), Some(v))
        }
        Some(TransformType::Minimum(operand)) => {
            let v = max_min(current.as_ref(), operand, false)?;
            (v.clone(), Some(v))
        }
        Some(TransformType::AppendMissingElements(operands)) => {
            let mut elements = as_array_elements(current);
            for op in &operands.values {
                if !elements.iter().any(|e| index_equal(e, op)) {
                    elements.push(op.clone());
                }
            }
            (null_value(), Some(array_value(elements)))
        }
        Some(TransformType::RemoveAllFromArray(operands)) => {
            let elements = as_array_elements(current)
                .into_iter()
                .filter(|e| !operands.values.iter().any(|op| index_equal(e, op)))
                .collect();
            (null_value(), Some(array_value(elements)))
        }
        None => return Err(EngineError::InvalidArgument("empty field transform".into())),
    };
    if let Some(v) = stored {
        set_field(fields, &transform.field_path, v);
    }
    Ok(result)
}

fn numeric(value: &Value) -> Option<Number> {
    match value.value_type.as_ref()? {
        ValueType::IntegerValue(i) => Some(Number::Int(*i)),
        ValueType::DoubleValue(d) => Some(Number::Double(*d)),
        _ => None,
    }
}

enum Number {
    Int(i64),
    Double(f64),
}

fn increment(current: Option<&Value>, operand: &Value) -> Result<Value, EngineError> {
    let Some(op) = numeric(operand) else {
        return Err(EngineError::InvalidArgument(
            "increment operand must be an integer or a double".into(),
        ));
    };
    // Missing or non-numeric current value: the operand wins.
    let Some(cur) = current.and_then(numeric) else {
        return Ok(operand.clone());
    };
    Ok(match (cur, op) {
        (Number::Int(a), Number::Int(b)) => int_value(
            // Saturating: positive overflow pins to MAX, negative to MIN.
            a.checked_add(b).unwrap_or(if b >= 0 { i64::MAX } else { i64::MIN }),
        ),
        (Number::Int(a), Number::Double(b)) => double_value(a as f64 + b),
        (Number::Double(a), Number::Int(b)) => double_value(a + b as f64),
        (Number::Double(a), Number::Double(b)) => double_value(a + b),
    })
}

fn max_min(current: Option<&Value>, operand: &Value, want_max: bool) -> Result<Value, EngineError> {
    let Some(op) = numeric(operand) else {
        return Err(EngineError::InvalidArgument(
            "maximum/minimum operand must be an integer or a double".into(),
        ));
    };
    let operand_nan = matches!(op, Number::Double(d) if d.is_nan());
    let Some(cur) = current else {
        return Ok(operand.clone());
    };
    let cur_num = numeric(cur);
    // Non-numeric current or NaN operand: the operand wins; NaN current wins
    // over a numeric operand.
    if cur_num.is_none() || operand_nan {
        return Ok(operand.clone());
    }
    if matches!(cur_num, Some(Number::Double(d)) if d.is_nan()) {
        return Ok(cur.clone());
    }
    let ordering = compare_values(cur, operand);
    let keep_current = if want_max { ordering.is_ge() } else { ordering.is_le() };
    Ok(if keep_current { cur.clone() } else { operand.clone() })
}

fn as_array_elements(value: Option<Value>) -> Vec<Value> {
    match value.and_then(|v| v.value_type) {
        Some(ValueType::ArrayValue(a)) => a.values,
        _ => Vec::new(),
    }
}

/// Index-value equality: `1 == 1.0`, NaN equals NaN — the dedup semantics of
/// array transforms.
fn index_equal(a: &Value, b: &Value) -> bool {
    encode_value(a) == encode_value(b)
}

fn null_value() -> Value {
    Value { value_type: Some(ValueType::NullValue(0)) }
}
fn int_value(i: i64) -> Value {
    Value { value_type: Some(ValueType::IntegerValue(i)) }
}
fn double_value(d: f64) -> Value {
    Value { value_type: Some(ValueType::DoubleValue(d)) }
}
fn array_value(values: Vec<Value>) -> Value {
    Value { value_type: Some(ValueType::ArrayValue(ArrayValue { values })) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_saturates_and_promotes() {
        let cur = int_value(i64::MAX - 1);
        assert_eq!(increment(Some(&cur), &int_value(10)).unwrap(), int_value(i64::MAX));
        let cur = int_value(i64::MIN + 1);
        assert_eq!(increment(Some(&cur), &int_value(-10)).unwrap(), int_value(i64::MIN));
        assert_eq!(increment(Some(&int_value(1)), &double_value(0.5)).unwrap(), double_value(1.5));
        assert_eq!(increment(None, &int_value(7)).unwrap(), int_value(7));
        assert_eq!(increment(Some(&null_value()), &int_value(7)).unwrap(), int_value(7));
        assert!(increment(Some(&int_value(1)), &null_value()).is_err());
    }

    #[test]
    fn max_min_nan_semantics() {
        let nan = double_value(f64::NAN);
        // NaN operand wins.
        let r = max_min(Some(&int_value(5)), &nan, true).unwrap();
        assert!(matches!(r.value_type, Some(ValueType::DoubleValue(d)) if d.is_nan()));
        // NaN current wins over numeric operand.
        let r = max_min(Some(&nan), &int_value(5), true).unwrap();
        assert!(matches!(r.value_type, Some(ValueType::DoubleValue(d)) if d.is_nan()));
        // Plain comparison, current kept on ties (preserves int-ness).
        assert_eq!(max_min(Some(&int_value(1)), &double_value(1.0), true).unwrap(), int_value(1));
        assert_eq!(max_min(Some(&int_value(3)), &int_value(5), true).unwrap(), int_value(5));
        assert_eq!(max_min(Some(&int_value(3)), &int_value(5), false).unwrap(), int_value(3));
        // Missing / non-numeric current: operand.
        assert_eq!(max_min(None, &int_value(5), false).unwrap(), int_value(5));
        assert_eq!(max_min(Some(&null_value()), &int_value(5), false).unwrap(), int_value(5));
    }

    #[test]
    fn array_transforms_dedup_by_index_equality() {
        let cur = array_value(vec![int_value(1), int_value(2)]);
        let mut state =
            DocState { current: Some((0, 0, HashMap::new())), before: None, dirty: false };
        state.current.as_mut().unwrap().2.insert("a".into(), cur);

        // 1.0 collides with existing 1; 3 appends.
        let t = FieldTransform {
            field_path: "a".into(),
            transform_type: Some(TransformType::AppendMissingElements(ArrayValue {
                values: vec![double_value(1.0), int_value(3)],
            })),
        };
        let result = apply_transform(&mut state, &t, 0).unwrap();
        assert_eq!(result, null_value());
        let (_, _, fields) = state.current.as_ref().unwrap();
        assert_eq!(
            get_field(fields, "a").unwrap(),
            &array_value(vec![int_value(1), int_value(2), int_value(3)])
        );

        let t = FieldTransform {
            field_path: "a".into(),
            transform_type: Some(TransformType::RemoveAllFromArray(ArrayValue {
                values: vec![double_value(2.0)],
            })),
        };
        apply_transform(&mut state, &t, 0).unwrap();
        let (_, _, fields) = state.current.as_ref().unwrap();
        assert_eq!(get_field(fields, "a").unwrap(), &array_value(vec![int_value(1), int_value(3)]));
    }
}
