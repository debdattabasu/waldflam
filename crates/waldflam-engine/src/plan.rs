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
//! **`Plan::exact` is a stronger claim** and is tracked separately: it says
//! the predicate matches the query's documents precisely, which is what lets
//! ordering and paging move into MongoDB. Widening a clause is always safe
//! for the predicate but must clear `exact`, or a server-side `limit` will
//! count documents the in-memory pass is about to reject.
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

/// A translated filter list.
pub struct Plan {
    /// The `$and` predicate, or `None` when nothing could be translated.
    pub predicate: Option<Document>,
    /// Whether the predicate matches *exactly* the documents the query does,
    /// rather than a superset.
    ///
    /// This is what licenses pushing `sort`/`skip`/`limit` into MongoDB. On a
    /// merely-sound predicate a server-side `limit: 10` could return ten
    /// candidates of which the in-memory pass rejects three — silently
    /// answering seven when more matches existed further down. Exact means
    /// nothing gets rejected afterwards, so the window is safe to apply early.
    pub exact: bool,
}

/// Builds the predicate for a flattened filter list. `order_paths` are the
/// normalized order-by fields, which Firestore requires to be present — an
/// exact condition, and one that has to be part of the predicate before a
/// window can be pushed down.
pub fn plan(filters: &[&FilterType], order_paths: &[&str]) -> Plan {
    let mut clauses = Vec::new();
    let mut exact = true;
    for filter in filters {
        match clause_for(filter) {
            Some((clause, clause_exact)) => {
                clauses.push(clause);
                exact &= clause_exact;
            }
            // Untranslatable: everything still matches, so the predicate is
            // wider than the query.
            None => exact = false,
        }
    }
    for path in order_paths {
        // `__name__` is always present; anything else must exist to sort by.
        if *path != "__name__" && plain_path(path).is_some() {
            clauses.push(exists(path));
        } else if *path != "__name__" {
            exact = false;
        }
    }
    let predicate = (!clauses.is_empty()).then(|| doc! { "$and": clauses });
    Plan { predicate, exact }
}

/// Convenience for callers that only want the predicate.
pub fn mongo_predicate(filters: &[&FilterType]) -> Option<Document> {
    plan(filters, &[]).predicate
}

/// Returns the clause and whether it is exact (as opposed to a superset).
fn clause_for(filter: &FilterType) -> Option<(Document, bool)> {
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
                    Some((entry(&path, "v", key(operand).into()), true))
                }
                // Type-bounded on both sides, so exact — see `range`.
                FieldOp::LessThan => range(&path, operand, "$lt"),
                FieldOp::LessThanOrEqual => range(&path, operand, "$lte"),
                FieldOp::GreaterThan => range(&path, operand, "$gt"),
                FieldOp::GreaterThanOrEqual => range(&path, operand, "$gte"),
                // Array membership rides the per-element "e" entries.
                FieldOp::ArrayContains => {
                    reject_null_nan(operand)?;
                    Some((entry(&path, "e", key(operand).into()), true))
                }
                FieldOp::ArrayContainsAny => {
                    Some((entry(&path, "e", doc! { "$in": key_set(operand)? }.into()), true))
                }
                FieldOp::In => {
                    Some((entry(&path, "v", doc! { "$in": key_set(operand)? }.into()), true))
                }
                // Negations: the most we can say cheaply is that the field
                // has to exist at all, which Firestore also requires. The
                // in-memory pass does the actual exclusion, so this is a
                // superset.
                FieldOp::NotEqual | FieldOp::NotIn => Some((exists(&path), false)),
                FieldOp::Unspecified => None,
            }
        }
        FilterType::UnaryFilter(u) => {
            let Some(OperandType::Field(field)) = u.operand_type.as_ref() else {
                return None;
            };
            let path = plain_path(&field.field_path)?;
            match u.op() {
                UnaryOp::IsNull => Some((entry(&path, "v", key(&null_value()).into()), true)),
                UnaryOp::IsNan => Some((entry(&path, "v", key(&nan_value()).into()), true)),
                // "not null" / "not NaN" still require the field to exist,
                // which is all we can say — a superset.
                UnaryOp::IsNotNull | UnaryOp::IsNotNan => Some((exists(&path), false)),
                UnaryOp::Unspecified => None,
            }
        }
        // run_query flattens AND trees before planning, and rejects OR.
        FilterType::CompositeFilter(_) => None,
    }
}

/// A type-bounded range. Firestore inequalities only compare within one type,
/// and an encoded key starts with its type's tag byte — so confining the key
/// to that tag's span *is* that rule, which makes the clause exact rather
/// than a superset, and so eligible for window pushdown.
fn range(path: &str, operand: &Value, op: &str) -> Option<(Document, bool)> {
    reject_null_nan(operand)?;
    let bound = key(operand);
    let tag = bound.get(0..2)?.to_owned();
    let mut cond = Document::new();
    cond.insert(op, &bound);
    if op == "$lt" || op == "$lte" {
        if is_number(operand) {
            // NaN is a number but never satisfies an inequality, and it
            // encodes below every real one — so flooring just above it both
            // excludes NaN and keeps the range inside the number tag.
            cond.insert("$gt", key(&nan_value()));
        } else {
            cond.insert("$gte", &tag);
        }
    } else {
        // Ceiling at the next tag value; no real type tag lands on tag + 1.
        let next = u8::from_str_radix(&tag, 16).ok()? + 1;
        cond.insert("$lt", format!("{next:02x}"));
    }
    Some((entry(path, "v", cond.into()), true))
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

/// Integers and doubles share one type rank, and one index tag.
fn is_number(v: &Value) -> bool {
    matches!(v.value_type, Some(ValueType::IntegerValue(_)) | Some(ValueType::DoubleValue(_)))
}

fn null_value() -> Value {
    Value { value_type: Some(ValueType::NullValue(0)) }
}

fn nan_value() -> Value {
    Value { value_type: Some(ValueType::DoubleValue(f64::NAN)) }
}
