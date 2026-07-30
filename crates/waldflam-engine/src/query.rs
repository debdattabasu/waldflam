//! StructuredQuery evaluation.
//!
//! M1 strategy (same as the official emulator): fetch the target collection,
//! then filter/sort/cursor in memory with the exact comparator. Index-backed
//! scans come later; semantics first.
//!
//! Implemented semantics (docs/architecture.md §3/§11): fields must exist to
//! match any filter or order-by; inequalities are type-bounded (same type
//! rank only); `== null`/`== NaN` never match (clients send unary filters);
//! implicit order-bys append inequality fields then `__name__`, all in the
//! last explicit direction.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use waldflam_proto::v1::structured_query::composite_filter::Operator as CompositeOp;
use waldflam_proto::v1::structured_query::field_filter::Operator as FieldOp;
use waldflam_proto::v1::structured_query::filter::FilterType;
use waldflam_proto::v1::structured_query::unary_filter::{OperandType, Operator as UnaryOp};
use waldflam_proto::v1::structured_query::{Direction, FieldReference, Filter, Order};
use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::{Cursor, StructuredQuery, Value, structured_aggregation_query};

use crate::EngineError;
use crate::fields::get_field;
use crate::order::{compare_values, same_type_rank};
use crate::path::{DatabaseName, ResourcePath};
use crate::store::{Store, StoredDocument};

pub async fn run_query(
    store: &Store,
    database: &DatabaseName,
    parent: &ResourcePath,
    query: &StructuredQuery,
) -> Result<Vec<StoredDocument>, EngineError> {
    let [selector] = query.from.as_slice() else {
        return Err(EngineError::InvalidArgument(
            "StructuredQuery.from must have exactly one collection selector".into(),
        ));
    };

    // Candidate set.
    let mut docs = if selector.all_descendants {
        if !parent.is_empty() {
            return Err(EngineError::Unimplemented("collection-group queries below the root"));
        }
        store.list_collection_group(database, &selector.collection_id).await?
    } else {
        let collection = parent.child(&selector.collection_id)?;
        store.list_collection(database, &collection).await?
    };

    // Filters.
    let mut filters = Vec::new();
    if let Some(filter) = query.r#where.as_ref() {
        flatten_and(filter, &mut filters)?;
    }
    docs.retain(|doc| filters.iter().all(|f| matches_filter(database, doc, f)));

    // Normalized order-bys: explicit, then inequality fields, then __name__.
    let orders = normalize_orders(query, &filters);

    // Order-by fields must exist (except __name__).
    docs.retain(|doc| {
        orders.iter().all(|o| {
            let path = order_path(o);
            path == "__name__" || get_field(&doc.fields, path).is_some()
        })
    });

    // Sort.
    docs.sort_by(|a, b| compare_docs(database, a, b, &orders));

    // Cursors.
    if let Some(start) = query.start_at.as_ref() {
        let start = validate_cursor(start, &orders)?;
        docs.retain(|doc| {
            let cmp = compare_doc_to_cursor(database, doc, start, &orders);
            cmp == Ordering::Greater || (cmp == Ordering::Equal && start.before)
        });
    }
    if let Some(end) = query.end_at.as_ref() {
        let end = validate_cursor(end, &orders)?;
        docs.retain(|doc| {
            let cmp = compare_doc_to_cursor(database, doc, end, &orders);
            cmp == Ordering::Less || (cmp == Ordering::Equal && !end.before)
        });
    }

    // Offset / limit.
    if query.offset > 0 {
        docs.drain(..(query.offset as usize).min(docs.len()));
    }
    if let Some(limit) = query.limit {
        docs.truncate(limit.max(0) as usize);
    }
    Ok(docs)
}

/// Computes aggregation results over an already-evaluated result set.
///
/// Semantics: `count` caps at `up_to`; `sum`/`avg` consider only numeric
/// values (missing/non-numeric fields are skipped, not zero); an integer sum
/// stays int64 until a double appears or it overflows, then promotes; any
/// NaN poisons the result; empty sum = int 0, empty avg = null.
pub fn aggregate(
    docs: &[StoredDocument],
    aggregations: &[structured_aggregation_query::Aggregation],
) -> Result<Vec<(String, Value)>, EngineError> {
    use structured_aggregation_query::aggregation::Operator;
    let mut out = Vec::with_capacity(aggregations.len());
    for (i, agg) in aggregations.iter().enumerate() {
        let alias = if agg.alias.is_empty() { format!("field_{i}") } else { agg.alias.clone() };
        let value = match agg.operator.as_ref() {
            Some(Operator::Count(count)) => {
                let mut n = docs.len() as i64;
                if let Some(up_to) = count.up_to {
                    n = n.min(up_to);
                }
                Value { value_type: Some(ValueType::IntegerValue(n)) }
            }
            Some(Operator::Sum(sum)) => {
                let field = sum.field.as_ref().map(|f| f.field_path.as_str()).unwrap_or("");
                numeric_fold(docs, field).into_sum()
            }
            Some(Operator::Avg(avg)) => {
                let field = avg.field.as_ref().map(|f| f.field_path.as_str()).unwrap_or("");
                numeric_fold(docs, field).into_avg()
            }
            None => {
                return Err(EngineError::InvalidArgument("aggregation has no operator".into()));
            }
        };
        out.push((alias, value));
    }
    Ok(out)
}

struct NumericFold {
    int_sum: Option<i64>,
    double_sum: f64,
    count: i64,
    seen_double: bool,
}

fn numeric_fold(docs: &[StoredDocument], field: &str) -> NumericFold {
    let mut fold = NumericFold { int_sum: Some(0), double_sum: 0.0, count: 0, seen_double: false };
    for doc in docs {
        match get_field(&doc.fields, field).and_then(|v| v.value_type.as_ref()) {
            Some(ValueType::IntegerValue(i)) => {
                fold.count += 1;
                fold.double_sum += *i as f64;
                fold.int_sum = fold.int_sum.and_then(|s| s.checked_add(*i));
            }
            Some(ValueType::DoubleValue(d)) => {
                fold.count += 1;
                fold.seen_double = true;
                fold.double_sum += d;
            }
            _ => {}
        }
    }
    fold
}

impl NumericFold {
    fn into_sum(self) -> Value {
        let vt = match (self.seen_double, self.int_sum) {
            // All ints, no overflow: stays an integer.
            (false, Some(s)) => ValueType::IntegerValue(s),
            _ => ValueType::DoubleValue(self.double_sum),
        };
        Value { value_type: Some(vt) }
    }

    fn into_avg(self) -> Value {
        let vt = if self.count == 0 {
            ValueType::NullValue(0)
        } else {
            ValueType::DoubleValue(self.double_sum / self.count as f64)
        };
        Value { value_type: Some(vt) }
    }
}

fn flatten_and<'a>(filter: &'a Filter, out: &mut Vec<&'a FilterType>) -> Result<(), EngineError> {
    match filter.filter_type.as_ref() {
        None => Ok(()),
        Some(FilterType::CompositeFilter(c)) => {
            if c.op() != CompositeOp::And {
                return Err(EngineError::Unimplemented("OR composite filters"));
            }
            for f in &c.filters {
                flatten_and(f, out)?;
            }
            Ok(())
        }
        Some(other) => {
            out.push(other);
            Ok(())
        }
    }
}

fn field_value(database: &DatabaseName, doc: &StoredDocument, path: &str) -> Option<Value> {
    if path == "__name__" {
        Some(Value {
            value_type: Some(ValueType::ReferenceValue(format!(
                "{}/{}",
                database.documents_root(),
                doc.path
            ))),
        })
    } else {
        get_field(&doc.fields, path).cloned()
    }
}

fn is_null(v: &Value) -> bool {
    matches!(v.value_type, None | Some(ValueType::NullValue(_)))
}

fn is_nan(v: &Value) -> bool {
    matches!(v.value_type, Some(ValueType::DoubleValue(d)) if d.is_nan())
}

/// Query equality: null and NaN operands never match (unary filters handle
/// them); values must share a type rank (int/double share Number).
fn query_eq(v: &Value, operand: &Value) -> bool {
    if is_null(operand) || is_nan(operand) || is_nan(v) {
        return false;
    }
    same_type_rank(v, operand) && compare_values(v, operand) == Ordering::Equal
}

fn matches_filter(database: &DatabaseName, doc: &StoredDocument, filter: &&FilterType) -> bool {
    match filter {
        FilterType::FieldFilter(f) => {
            let Some(field) = f.field.as_ref() else {
                return false;
            };
            let Some(operand) = f.value.as_ref() else {
                return false;
            };
            let Some(v) = field_value(database, doc, &field.field_path) else {
                return false; // field must exist
            };
            match f.op() {
                FieldOp::Equal => query_eq(&v, operand),
                FieldOp::NotEqual => {
                    !is_null(&v) && !is_nan(&v) && !is_null(operand) && !query_eq(&v, operand)
                }
                FieldOp::LessThan => inequality(&v, operand, Ordering::Less, false),
                FieldOp::LessThanOrEqual => inequality(&v, operand, Ordering::Less, true),
                FieldOp::GreaterThan => inequality(&v, operand, Ordering::Greater, false),
                FieldOp::GreaterThanOrEqual => inequality(&v, operand, Ordering::Greater, true),
                FieldOp::ArrayContains => {
                    array_elements(&v).is_some_and(|els| els.iter().any(|e| query_eq(e, operand)))
                }
                FieldOp::In => {
                    array_elements(operand).is_some_and(|ops| ops.iter().any(|o| query_eq(&v, o)))
                }
                FieldOp::ArrayContainsAny => match (array_elements(&v), array_elements(operand)) {
                    (Some(els), Some(ops)) => {
                        els.iter().any(|e| ops.iter().any(|o| query_eq(e, o)))
                    }
                    _ => false,
                },
                FieldOp::NotIn => {
                    !is_null(&v)
                        && !is_nan(&v)
                        && array_elements(operand).is_some_and(|ops| {
                            !ops.iter().any(is_null) && !ops.iter().any(|o| query_eq(&v, o))
                        })
                }
                FieldOp::Unspecified => false,
            }
        }
        FilterType::UnaryFilter(u) => {
            let Some(OperandType::Field(field)) = u.operand_type.as_ref() else {
                return false;
            };
            let value = field_value(database, doc, &field.field_path);
            match u.op() {
                UnaryOp::IsNull => value.as_ref().is_some_and(is_null),
                UnaryOp::IsNan => value.as_ref().is_some_and(is_nan),
                UnaryOp::IsNotNull => value.as_ref().is_some_and(|v| !is_null(v)),
                UnaryOp::IsNotNan => value.as_ref().is_some_and(|v| !is_null(v) && !is_nan(v)),
                UnaryOp::Unspecified => false,
            }
        }
        FilterType::CompositeFilter(_) => unreachable!("flattened"),
    }
}

/// Type-bounded inequality: only same-rank values compare, NaN never matches.
fn inequality(v: &Value, operand: &Value, want: Ordering, or_equal: bool) -> bool {
    if is_nan(v) || is_nan(operand) || is_null(operand) || !same_type_rank(v, operand) {
        return false;
    }
    let ord = compare_values(v, operand);
    ord == want || (or_equal && ord == Ordering::Equal)
}

fn array_elements(v: &Value) -> Option<&[Value]> {
    match v.value_type.as_ref()? {
        ValueType::ArrayValue(a) => Some(&a.values),
        _ => None,
    }
}

fn order_path(order: &Order) -> &str {
    order.field.as_ref().map(|f| f.field_path.as_str()).unwrap_or("")
}

fn normalize_orders(query: &StructuredQuery, filters: &[&FilterType]) -> Vec<Order> {
    let mut orders = query.order_by.clone();
    let last_direction = orders.last().map(|o| o.direction).unwrap_or(Direction::Ascending as i32);
    let present: BTreeSet<String> = orders.iter().map(|o| order_path(o).to_owned()).collect();

    // Inequality-filtered fields, in canonical path order.
    let mut inequality_paths = BTreeSet::new();
    for f in filters {
        if let FilterType::FieldFilter(ff) = f {
            let is_inequality = matches!(
                ff.op(),
                FieldOp::LessThan
                    | FieldOp::LessThanOrEqual
                    | FieldOp::GreaterThan
                    | FieldOp::GreaterThanOrEqual
                    | FieldOp::NotEqual
                    | FieldOp::NotIn
            );
            if is_inequality && let Some(field) = ff.field.as_ref() {
                inequality_paths.insert(field.field_path.clone());
            }
        }
    }
    for path in inequality_paths {
        if !present.contains(&path) && path != "__name__" {
            orders.push(Order {
                field: Some(FieldReference { field_path: path }),
                direction: last_direction,
            });
        }
    }
    if !present.contains("__name__") && !orders.iter().any(|o| order_path(o) == "__name__") {
        orders.push(Order {
            field: Some(FieldReference { field_path: "__name__".into() }),
            direction: last_direction,
        });
    }
    orders
}

fn apply_direction(ord: Ordering, direction: i32) -> Ordering {
    if direction == Direction::Descending as i32 { ord.reverse() } else { ord }
}

fn compare_docs(
    database: &DatabaseName,
    a: &StoredDocument,
    b: &StoredDocument,
    orders: &[Order],
) -> Ordering {
    for order in orders {
        let path = order_path(order);
        // Order-by fields were checked for existence; __name__ always exists.
        let (Some(va), Some(vb)) = (field_value(database, a, path), field_value(database, b, path))
        else {
            continue;
        };
        let ord = apply_direction(compare_values(&va, &vb), order.direction);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

fn validate_cursor<'a>(cursor: &'a Cursor, orders: &[Order]) -> Result<&'a Cursor, EngineError> {
    if cursor.values.len() > orders.len() {
        return Err(EngineError::InvalidArgument("cursor has too many values".into()));
    }
    Ok(cursor)
}

fn compare_doc_to_cursor(
    database: &DatabaseName,
    doc: &StoredDocument,
    cursor: &Cursor,
    orders: &[Order],
) -> Ordering {
    for (cursor_value, order) in cursor.values.iter().zip(orders) {
        let Some(v) = field_value(database, doc, order_path(order)) else {
            continue;
        };
        let ord = apply_direction(compare_values(&v, cursor_value), order.direction);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}
