//! Query planning: turning `StructuredQuery` filters into a MongoDB
//! predicate over the `indexed` entries every document carries.
//!
//! **Soundness rule.** The predicate is allowed to match *more* documents
//! than the query does, but never fewer. `query::run_query` still applies the
//! exact Firestore semantics in memory to whatever comes back, so an
//! over-broad predicate only costs I/O, while an over-narrow one would drop
//! results. Every translation below is therefore either exact or a documented
//! superset, and anything that can't be translated confidently is skipped —
//! a skipped filter just isn't part of the predicate.
//!
//! The index keys make this work: `index_key::encode_value` is
//! order-preserving across the whole cross-type ordering, so equality is byte
//! equality and Firestore's ranges are sub-ranges of Mongo's.
//!
//! **Only one clause is selective.** MongoDB applies one `$elemMatch` per
//! index scan, so with several filters it seeks on one and applies the rest
//! while fetching. Emitting all of them is still worth it — the planner
//! picks, and the others narrow nothing but cost nothing — but no arrangement
//! of clauses here makes a second filter selective. That needs a composite
//! index keyed per query shape, which the single `indexed` array cannot
//! express; see architecture.md §9 and backlog.md.

use mongodb::bson::{Bson, Document, doc};
use waldflam_proto::v1::Value;
use waldflam_proto::v1::structured_query::field_filter::Operator as FieldOp;
use waldflam_proto::v1::structured_query::filter::FilterType;
use waldflam_proto::v1::structured_query::unary_filter::{OperandType, Operator as UnaryOp};
use waldflam_proto::v1::value::ValueType;

use crate::index_key::{encode_value, to_index_string};

/// Builds the `$and` predicate for a flattened filter list, or `None` when
/// nothing could be translated (the caller then scans as before).
pub fn mongo_predicate(filters: &[&FilterType]) -> Option<Document> {
    let clauses: Vec<Document> = filters.iter().filter_map(|f| clause_for(f)).collect();
    if clauses.is_empty() {
        return None;
    }
    Some(doc! { "$and": clauses })
}

fn clause_for(filter: &FilterType) -> Option<Document> {
    match filter {
        FilterType::FieldFilter(f) => {
            let path = plain_path(f.field.as_ref()?.field_path.as_str())?;
            let operand = f.value.as_ref()?;
            match f.op() {
                // Equal values encode identically and unequal ones don't, so
                // byte equality *is* Firestore equality — including `1` vs
                // `1.0`. Null and NaN operands never match anything, and the
                // in-memory pass already rejects them; skip rather than
                // encode a value that means something else in index space.
                FieldOp::Equal => {
                    reject_null_nan(operand)?;
                    Some(entry(&path, "v", key(operand).into()))
                }
                // Superset: Firestore inequalities are type-bounded, Mongo's
                // range is not, so lower/higher type ranks come along and get
                // trimmed in memory. The bound itself can stay strict —
                // distinct values never share a key, so nothing that should
                // match sits exactly on it.
                FieldOp::LessThan => {
                    reject_null_nan(operand)?;
                    Some(entry(&path, "v", doc! { "$lt": key(operand) }.into()))
                }
                FieldOp::LessThanOrEqual => {
                    reject_null_nan(operand)?;
                    Some(entry(&path, "v", doc! { "$lte": key(operand) }.into()))
                }
                FieldOp::GreaterThan => {
                    reject_null_nan(operand)?;
                    Some(entry(&path, "v", doc! { "$gt": key(operand) }.into()))
                }
                FieldOp::GreaterThanOrEqual => {
                    reject_null_nan(operand)?;
                    Some(entry(&path, "v", doc! { "$gte": key(operand) }.into()))
                }
                // Array membership rides the per-element "e" entries.
                FieldOp::ArrayContains => {
                    reject_null_nan(operand)?;
                    Some(entry(&path, "e", key(operand).into()))
                }
                FieldOp::ArrayContainsAny => {
                    Some(entry(&path, "e", doc! { "$in": key_set(operand)? }.into()))
                }
                FieldOp::In => Some(entry(&path, "v", doc! { "$in": key_set(operand)? }.into())),
                // Negations: the most we can say cheaply is that the field
                // has to exist at all, which Firestore also requires. The
                // in-memory pass does the actual exclusion.
                FieldOp::NotEqual | FieldOp::NotIn => Some(exists(&path)),
                FieldOp::Unspecified => None,
            }
        }
        FilterType::UnaryFilter(u) => {
            let Some(OperandType::Field(field)) = u.operand_type.as_ref() else {
                return None;
            };
            let path = plain_path(&field.field_path)?;
            match u.op() {
                UnaryOp::IsNull => Some(entry(&path, "v", key(&null_value()).into())),
                UnaryOp::IsNan => Some(entry(&path, "v", key(&nan_value()).into())),
                // "not null" / "not NaN" still require the field to exist.
                UnaryOp::IsNotNull | UnaryOp::IsNotNan => Some(exists(&path)),
                UnaryOp::Unspecified => None,
            }
        }
        // run_query flattens AND trees before planning, and rejects OR.
        FilterType::CompositeFilter(_) => None,
    }
}

/// Matches documents having an index entry for `path` of kind `kind` whose
/// key satisfies `value`.
fn entry(path: &str, kind: &str, value: Bson) -> Document {
    doc! { "indexed": { "$elemMatch": { "p": path, "k": kind, "v": value } } }
}

/// Matches documents where `path` is present at all.
fn exists(path: &str) -> Document {
    doc! { "indexed": { "$elemMatch": { "p": path, "k": "v" } } }
}

fn key(value: &Value) -> String {
    to_index_string(&encode_value(value))
}

/// Encoded keys for an array operand, dropping null/NaN entries — they never
/// match, so leaving them out keeps the match set identical.
fn key_set(operand: &Value) -> Option<Vec<String>> {
    let ValueType::ArrayValue(array) = operand.value_type.as_ref()? else {
        return None;
    };
    let keys: Vec<String> =
        array.values.iter().filter(|v| !is_null(v) && !is_nan(v)).map(key).collect();
    // An operand list with nothing matchable in it: let the in-memory pass
    // reject, rather than emitting an `$in: []` that means the same thing by
    // accident.
    (!keys.is_empty()).then_some(keys)
}

/// Field paths are stored as dotted joins, so a backtick-escaped path (the
/// syntax for a field whose *name* contains a dot) is ambiguous against a
/// nested map path. Refuse to plan those rather than risk excluding a match.
fn plain_path(path: &str) -> Option<String> {
    (!path.contains('`')).then(|| path.to_owned())
}

fn reject_null_nan(value: &Value) -> Option<()> {
    (!is_null(value) && !is_nan(value)).then_some(())
}

fn is_null(v: &Value) -> bool {
    matches!(v.value_type, None | Some(ValueType::NullValue(_)))
}

fn is_nan(v: &Value) -> bool {
    matches!(v.value_type, Some(ValueType::DoubleValue(d)) if d.is_nan())
}

fn null_value() -> Value {
    Value { value_type: Some(ValueType::NullValue(0)) }
}

fn nan_value() -> Value {
    Value { value_type: Some(ValueType::DoubleValue(f64::NAN)) }
}
