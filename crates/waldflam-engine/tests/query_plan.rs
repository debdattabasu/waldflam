//! Index-backed query planning, against a real MongoDB (docker compose up -d).
//!
//! Two properties. The planner must never drop a document the query matches —
//! checked differentially against `run_query_scanning`, which considers the
//! whole collection. And the predicate must actually be served by an index
//! rather than a collection scan — checked with MongoDB's own `explain`.

use std::collections::HashMap;

use mongodb::bson::doc;
use waldflam_engine::commit::apply_commit;
use waldflam_engine::path::{DatabaseName, ResourcePath};
use waldflam_engine::query::{run_query, run_query_scanning};
use waldflam_engine::store::Store;
use waldflam_proto::v1::structured_query::field_filter::Operator as FieldOp;
use waldflam_proto::v1::structured_query::filter::FilterType;
use waldflam_proto::v1::structured_query::unary_filter::{OperandType, Operator as UnaryOp};
use waldflam_proto::v1::structured_query::{
    CollectionSelector, Direction, FieldFilter, FieldReference, Filter, Order, UnaryFilter,
};
use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::write::Operation;
use waldflam_proto::v1::{ArrayValue, Cursor, Document, StructuredQuery, Value, Write};

fn uri() -> String {
    std::env::var("WALDFLAM_TEST_MONGO")
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017/?directConnection=true".into())
}

async fn store() -> Store {
    Store::connect(&uri()).await.expect("MongoDB not reachable — run `docker compose up -d`")
}

fn test_db(label: &str) -> DatabaseName {
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    DatabaseName::new(format!("plan-{label}-{nanos}"), "(default)")
}

fn val(vt: ValueType) -> Value {
    Value { value_type: Some(vt) }
}
fn int(i: i64) -> Value {
    val(ValueType::IntegerValue(i))
}
fn string(s: &str) -> Value {
    val(ValueType::StringValue(s.into()))
}
fn array(values: Vec<Value>) -> Value {
    val(ValueType::ArrayValue(ArrayValue { values }))
}

fn set_write(name: &str, fields: HashMap<String, Value>) -> Write {
    Write {
        operation: Some(Operation::Update(Document {
            name: name.into(),
            fields,
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn field_filter(path: &str, op: FieldOp, value: Value) -> Filter {
    Filter {
        filter_type: Some(FilterType::FieldFilter(FieldFilter {
            field: Some(FieldReference { field_path: path.into() }),
            op: op as i32,
            value: Some(value),
        })),
    }
}

fn unary_filter(path: &str, op: UnaryOp) -> Filter {
    Filter {
        filter_type: Some(FilterType::UnaryFilter(UnaryFilter {
            op: op as i32,
            operand_type: Some(OperandType::Field(FieldReference { field_path: path.into() })),
        })),
    }
}

fn query_on(collection: &str, filter: Option<Filter>) -> StructuredQuery {
    StructuredQuery {
        from: vec![CollectionSelector { collection_id: collection.into(), all_descendants: false }],
        r#where: filter,
        ..Default::default()
    }
}

/// A corpus spanning the value types and shapes the planner translates:
/// scalars of several types, arrays, nested maps, missing fields, null and
/// NaN — so a predicate that is wrong about any of them shows up.
async fn seed(store: &Store, db: &DatabaseName, collection: &str) {
    let root = db.documents_root();
    let mut writes = Vec::new();
    for i in 0..40i64 {
        let mut fields = HashMap::new();
        fields.insert("n".into(), int(i));
        fields.insert("name".into(), string(&format!("doc-{i:02}")));
        fields.insert("even".into(), val(ValueType::BooleanValue(i % 2 == 0)));
        // Integral doubles must dedupe against ints in index space.
        fields.insert(
            "mixed".into(),
            if i % 3 == 0 { val(ValueType::DoubleValue(i as f64)) } else { int(i) },
        );
        fields.insert("tags".into(), array(vec![string(&format!("t{}", i % 5)), string("all")]));
        fields.insert(
            "meta".into(),
            val(ValueType::MapValue(waldflam_proto::v1::MapValue {
                fields: HashMap::from([("group".to_owned(), int(i % 4))]),
            })),
        );
        // A few documents deviate: missing field, explicit null, NaN.
        if i % 7 == 0 {
            fields.remove("name");
        }
        if i % 11 == 0 {
            fields.insert("maybe".into(), val(ValueType::NullValue(0)));
        } else if i % 13 == 0 {
            fields.insert("maybe".into(), val(ValueType::DoubleValue(f64::NAN)));
        } else if i % 5 == 0 {
            fields.insert("maybe".into(), int(i));
        }
        writes.push(set_write(&format!("{root}/{collection}/d{i:02}"), fields));
    }
    // Batches of 40 writes in one commit are fine; keep it to one round trip.
    apply_commit(store, db, &writes, 1_000).await.expect("seed commits");
}

fn shapes() -> Vec<(&'static str, Option<Filter>)> {
    vec![
        ("no filter", None),
        ("eq int", Some(field_filter("n", FieldOp::Equal, int(7)))),
        ("eq string", Some(field_filter("name", FieldOp::Equal, string("doc-03")))),
        ("eq bool", Some(field_filter("even", FieldOp::Equal, val(ValueType::BooleanValue(true))))),
        // 9.0 must find the document storing integer 9 and vice versa.
        (
            "eq double-vs-int",
            Some(field_filter("mixed", FieldOp::Equal, val(ValueType::DoubleValue(9.0)))),
        ),
        ("eq int-vs-double", Some(field_filter("mixed", FieldOp::Equal, int(12)))),
        ("eq nested map field", Some(field_filter("meta.group", FieldOp::Equal, int(2)))),
        ("lt", Some(field_filter("n", FieldOp::LessThan, int(10)))),
        ("lte", Some(field_filter("n", FieldOp::LessThanOrEqual, int(10)))),
        ("gt", Some(field_filter("n", FieldOp::GreaterThan, int(30)))),
        ("gte", Some(field_filter("n", FieldOp::GreaterThanOrEqual, int(30)))),
        ("gt string", Some(field_filter("name", FieldOp::GreaterThan, string("doc-20")))),
        ("array-contains", Some(field_filter("tags", FieldOp::ArrayContains, string("t3")))),
        (
            "array-contains common",
            Some(field_filter("tags", FieldOp::ArrayContains, string("all"))),
        ),
        (
            "array-contains-any",
            Some(field_filter(
                "tags",
                FieldOp::ArrayContainsAny,
                array(vec![string("t1"), string("t4")]),
            )),
        ),
        ("in", Some(field_filter("n", FieldOp::In, array(vec![int(1), int(5), int(9)])))),
        (
            "in with null operand",
            Some(field_filter("n", FieldOp::In, array(vec![int(2), val(ValueType::NullValue(0))]))),
        ),
        ("not-equal", Some(field_filter("n", FieldOp::NotEqual, int(5)))),
        ("not-in", Some(field_filter("n", FieldOp::NotIn, array(vec![int(1), int(2)])))),
        ("is-null", Some(unary_filter("maybe", UnaryOp::IsNull))),
        ("is-nan", Some(unary_filter("maybe", UnaryOp::IsNan))),
        ("is-not-null", Some(unary_filter("maybe", UnaryOp::IsNotNull))),
        ("is-not-nan", Some(unary_filter("maybe", UnaryOp::IsNotNan))),
        (
            "eq on missing-in-some field",
            Some(field_filter("name", FieldOp::Equal, string("doc-07"))),
        ),
        ("eq matching nothing", Some(field_filter("n", FieldOp::Equal, int(9_999)))),
        // Operands that never match anything, so nothing may be planned.
        ("eq null operand", Some(field_filter("n", FieldOp::Equal, val(ValueType::NullValue(0))))),
        (
            "eq NaN operand",
            Some(field_filter("n", FieldOp::Equal, val(ValueType::DoubleValue(f64::NAN)))),
        ),
    ]
}

fn order(path: &str, ascending: bool) -> Order {
    Order {
        field: Some(FieldReference { field_path: path.into() }),
        direction: if ascending { Direction::Ascending } else { Direction::Descending } as i32,
    }
}

/// Query shapes that reach the sort/skip/limit pushdown — the ones with a
/// window to push. Ordering and paging move into MongoDB only when the
/// predicate is exact, so these deliberately mix exact filters (which push)
/// with inexact ones like `!=` (which must not), and check both come back
/// identical to scanning.
#[allow(clippy::type_complexity)]
fn windowed_shapes() -> Vec<(&'static str, Option<Filter>, Vec<Order>, Option<i32>, i32)> {
    vec![
        ("order n asc, limit 5", None, vec![order("n", true)], Some(5), 0),
        ("order n desc, limit 5", None, vec![order("n", false)], Some(5), 0),
        ("order n asc, offset 5 limit 5", None, vec![order("n", true)], Some(5), 5),
        ("order n asc, offset only", None, vec![order("n", true)], None, 30),
        ("order name asc, limit 3 (missing on some)", None, vec![order("name", true)], Some(3), 0),
        ("order __name__ desc, limit 4", None, vec![order("__name__", false)], Some(4), 0),
        (
            "multi-field order, limit 7",
            None,
            vec![order("meta.group", true), order("n", false)],
            Some(7),
            0,
        ),
        // Mixed int/double storage must order as one number type.
        ("order mixed asc, limit 6", None, vec![order("mixed", true)], Some(6), 0),
        // Exact filters: these push.
        (
            "eq + order + limit",
            Some(field_filter("even", FieldOp::Equal, val(ValueType::BooleanValue(true)))),
            vec![order("n", true)],
            Some(4),
            0,
        ),
        (
            "array-contains + order + limit",
            Some(field_filter("tags", FieldOp::ArrayContains, string("all"))),
            vec![order("n", false)],
            Some(6),
            2,
        ),
        (
            "in + order + limit",
            Some(field_filter("n", FieldOp::In, array(vec![int(3), int(8), int(21)]))),
            vec![order("n", true)],
            Some(2),
            0,
        ),
        // Type-bounded ranges are exact too, so these push.
        (
            "range + order + limit",
            Some(field_filter("n", FieldOp::GreaterThanOrEqual, int(10))),
            vec![order("n", true)],
            Some(5),
            0,
        ),
        (
            "range desc + order + limit",
            Some(field_filter("n", FieldOp::LessThan, int(25))),
            vec![order("n", false)],
            Some(5),
            3,
        ),
        (
            "string range + order + limit",
            Some(field_filter("name", FieldOp::GreaterThan, string("doc-20"))),
            vec![order("name", true)],
            Some(4),
            0,
        ),
        // Inexact filters: must fall back rather than truncate early.
        (
            "not-equal + order + limit",
            Some(field_filter("n", FieldOp::NotEqual, int(5))),
            vec![order("n", true)],
            Some(5),
            0,
        ),
        (
            "is-not-null + order + limit",
            Some(unary_filter("maybe", UnaryOp::IsNotNull)),
            vec![order("n", true)],
            Some(3),
            0,
        ),
        // Degenerate windows.
        ("limit 0", None, vec![order("n", true)], Some(0), 0),
        ("limit past the end", None, vec![order("n", true)], Some(500), 0),
        ("offset past the end", None, vec![order("n", true)], Some(5), 500),
    ]
}

/// The soundness invariant: planning may only reduce I/O, never results.
#[tokio::test]
async fn planning_returns_exactly_what_scanning_returns() {
    let store = store().await;
    let db = test_db("differential");
    seed(&store, &db, "items").await;
    let root = ResourcePath::parse("").unwrap();

    let mut checked_nonempty = 0;
    for (label, filter) in shapes() {
        let query = query_on("items", filter);
        let planned = run_query(&store, &db, &root, &query).await.expect(label);
        let scanned = run_query_scanning(&store, &db, &root, &query).await.expect(label);

        let planned: Vec<String> = planned.iter().map(|d| d.path.to_string()).collect();
        let scanned: Vec<String> = scanned.iter().map(|d| d.path.to_string()).collect();
        assert_eq!(planned, scanned, "planner changed results for `{label}`");
        if !scanned.is_empty() {
            checked_nonempty += 1;
        }
    }
    // Guards against the whole corpus silently matching nothing, which would
    // make every comparison above trivially true.
    assert!(checked_nonempty >= 20, "only {checked_nonempty} shapes matched anything");
}

/// Ordering and paging pushed into MongoDB must select the same page the
/// in-memory pipeline would. This is the sharp end: the server-side `$sort`
/// runs on index keys lifted out of the `indexed` array, so a wrong
/// extraction, a flipped direction, or a limit applied to a merely-sound
/// predicate all show up as a different page.
#[tokio::test]
async fn pushed_down_windows_select_the_same_page() {
    let store = store().await;
    let db = test_db("windows");
    seed(&store, &db, "items").await;
    let root = ResourcePath::parse("").unwrap();

    for (label, filter, order_by, limit, offset) in windowed_shapes() {
        let query = StructuredQuery {
            from: vec![CollectionSelector {
                collection_id: "items".into(),
                all_descendants: false,
            }],
            r#where: filter,
            order_by,
            limit,
            offset,
            ..Default::default()
        };
        let planned = run_query(&store, &db, &root, &query).await.expect(label);
        let scanned = run_query_scanning(&store, &db, &root, &query).await.expect(label);

        // Order matters here, not just membership — this is a paged query.
        let planned: Vec<String> = planned.iter().map(|d| d.path.to_string()).collect();
        let scanned: Vec<String> = scanned.iter().map(|d| d.path.to_string()).collect();
        assert_eq!(planned, scanned, "pushdown changed the page for `{label}`");
    }
}

/// The differential tests only mean something if the window actually moves
/// server-side, and it only moves when the predicate is exact. Pin that
/// classification down directly, so a regression that quietly stops pushing
/// (or starts pushing when it shouldn't) fails here rather than going unseen.
#[test]
fn exactness_gates_pushdown_where_expected() {
    let exact_cases: Vec<(&str, FilterType)> = vec![
        ("equality", filter_type(field_filter("n", FieldOp::Equal, int(7)))),
        ("array-contains", filter_type(field_filter("tags", FieldOp::ArrayContains, string("a")))),
        ("in", filter_type(field_filter("n", FieldOp::In, array(vec![int(1), int(2)])))),
        ("range", filter_type(field_filter("n", FieldOp::GreaterThan, int(3)))),
        ("string range", filter_type(field_filter("s", FieldOp::LessThanOrEqual, string("m")))),
        ("is-null", filter_type(unary_filter("maybe", UnaryOp::IsNull))),
        ("is-nan", filter_type(unary_filter("maybe", UnaryOp::IsNan))),
    ];
    for (label, filter) in &exact_cases {
        let plan = waldflam_engine::plan::plan(&[filter], &["__name__"]);
        assert!(plan.exact, "`{label}` should be exact, so a window can be pushed");
        assert!(plan.predicate.is_some(), "`{label}` should produce a predicate");
    }

    let inexact_cases: Vec<(&str, FilterType)> = vec![
        ("not-equal", filter_type(field_filter("n", FieldOp::NotEqual, int(7)))),
        ("not-in", filter_type(field_filter("n", FieldOp::NotIn, array(vec![int(1)])))),
        ("is-not-null", filter_type(unary_filter("maybe", UnaryOp::IsNotNull))),
        ("is-not-nan", filter_type(unary_filter("maybe", UnaryOp::IsNotNan))),
        // Null and NaN operands never match, so nothing is translated at all.
        (
            "null operand",
            filter_type(field_filter("n", FieldOp::Equal, val(ValueType::NullValue(0)))),
        ),
    ];
    for (label, filter) in &inexact_cases {
        let plan = waldflam_engine::plan::plan(&[filter], &["__name__"]);
        assert!(!plan.exact, "`{label}` is a superset, so no window may be pushed");
    }
}

fn filter_type(filter: Filter) -> FilterType {
    filter.filter_type.expect("constructed with a filter type")
}

/// The plan MongoDB actually ran. `rejectedPlans` holds the alternatives it
/// considered — asserting against the whole explain document would match
/// stages that never executed.
fn winning_plan(explain: &mongodb::bson::Document) -> String {
    explain
        .get_document("queryPlanner")
        .and_then(|planner| planner.get_document("winningPlan"))
        .expect("queryPlanner.winningPlan")
        .to_string()
}

fn reference(db: &DatabaseName, path: &str) -> Value {
    val(ValueType::ReferenceValue(format!("{}/{}", db.documents_root(), path)))
}

fn cursor(values: Vec<Value>, before: bool) -> Cursor {
    Cursor { values, before }
}

/// Cursor shapes. `before` is Firestore's "position before this value", so
/// `start_at` includes it and `end_at` excludes it — the two cursors read
/// oppositely from the same flag, which is exactly the kind of thing a
/// differential test should pin down.
#[allow(clippy::type_complexity)]
fn cursor_shapes(
    db: &DatabaseName,
) -> Vec<(&'static str, Option<Filter>, Vec<Order>, Option<Cursor>, Option<Cursor>, Option<i32>)> {
    vec![
        (
            "startAt(n=10) asc",
            None,
            vec![order("n", true)],
            Some(cursor(vec![int(10)], true)),
            None,
            Some(5),
        ),
        (
            "startAfter(n=10) asc",
            None,
            vec![order("n", true)],
            Some(cursor(vec![int(10)], false)),
            None,
            Some(5),
        ),
        (
            "endAt(n=10) asc",
            None,
            vec![order("n", true)],
            None,
            Some(cursor(vec![int(10)], false)),
            Some(50),
        ),
        (
            "endBefore(n=10) asc",
            None,
            vec![order("n", true)],
            None,
            Some(cursor(vec![int(10)], true)),
            Some(50),
        ),
        (
            "startAt + endAt window",
            None,
            vec![order("n", true)],
            Some(cursor(vec![int(10)], true)),
            Some(cursor(vec![int(20)], false)),
            Some(50),
        ),
        (
            "startAt(n=30) desc",
            None,
            vec![order("n", false)],
            Some(cursor(vec![int(30)], true)),
            None,
            Some(6),
        ),
        (
            "endBefore(n=10) desc",
            None,
            vec![order("n", false)],
            None,
            Some(cursor(vec![int(10)], true)),
            Some(50),
        ),
        // Two-value keyset cursor: the `$or` expansion, and what a client
        // sends when paging from a document snapshot.
        (
            "startAfter(n=10, __name__=d10)",
            None,
            vec![order("n", true)],
            Some(cursor(vec![int(10), reference(db, "items/d10")], false)),
            None,
            Some(5),
        ),
        (
            "startAt(n=10, __name__=d10) inclusive",
            None,
            vec![order("n", true)],
            Some(cursor(vec![int(10), reference(db, "items/d10")], true)),
            None,
            Some(5),
        ),
        // Cursor shorter than the normalized order-by.
        (
            "startAfter(group=1) with two orders",
            None,
            vec![order("meta.group", true), order("n", true)],
            Some(cursor(vec![int(1)], false)),
            None,
            Some(8),
        ),
        (
            "string cursor",
            None,
            vec![order("name", true)],
            Some(cursor(vec![string("doc-15")], false)),
            None,
            Some(4),
        ),
        // With filters, exact and inexact.
        (
            "eq filter + startAfter",
            Some(field_filter("even", FieldOp::Equal, val(ValueType::BooleanValue(true)))),
            vec![order("n", true)],
            Some(cursor(vec![int(10)], false)),
            None,
            Some(4),
        ),
        (
            "range filter + startAt + endAt",
            Some(field_filter("n", FieldOp::GreaterThanOrEqual, int(5))),
            vec![order("n", true)],
            Some(cursor(vec![int(12)], true)),
            Some(cursor(vec![int(25)], false)),
            Some(6),
        ),
        (
            "inexact filter + cursor",
            Some(field_filter("n", FieldOp::NotEqual, int(15))),
            vec![order("n", true)],
            Some(cursor(vec![int(10)], false)),
            None,
            Some(5),
        ),
        // Degenerate: an empty cursor must not be pushed.
        (
            "empty cursor values",
            None,
            vec![order("n", true)],
            Some(cursor(vec![], false)),
            None,
            Some(5),
        ),
        (
            "no limit, cursor only",
            None,
            vec![order("n", true)],
            Some(cursor(vec![int(35)], false)),
            None,
            None,
        ),
    ]
}

/// Cursor pagination pushed into MongoDB must select the same page the
/// in-memory comparison would.
#[tokio::test]
async fn cursor_pages_match_scanning() {
    let store = store().await;
    let db = test_db("cursors");
    seed(&store, &db, "items").await;
    let root = ResourcePath::parse("").unwrap();

    for (label, filter, order_by, start_at, end_at, limit) in cursor_shapes(&db) {
        let query = StructuredQuery {
            from: vec![CollectionSelector {
                collection_id: "items".into(),
                all_descendants: false,
            }],
            r#where: filter,
            order_by,
            start_at,
            end_at,
            limit,
            ..Default::default()
        };
        let planned = run_query(&store, &db, &root, &query).await.expect(label);
        let scanned = run_query_scanning(&store, &db, &root, &query).await.expect(label);

        let planned: Vec<String> = planned.iter().map(|d| d.path.to_string()).collect();
        let scanned: Vec<String> = scanned.iter().map(|d| d.path.to_string()).collect();
        assert_eq!(planned, scanned, "cursor pushdown changed the page for `{label}`");
    }
}

/// The point of storing sort keys as real fields: MongoDB must answer
/// `ORDER BY <field>, __name__ LIMIT n` from the index and stop at n, instead
/// of ranking every candidate. A blocking `SORT` stage here means the
/// wildcard index stopped covering the order — which still returns correct
/// results, so only the plan reveals it.
#[tokio::test]
async fn sorted_pages_avoid_a_blocking_sort() {
    let store = store().await;
    let db = test_db("nosort");
    seed(&store, &db, "items").await;
    let root = ResourcePath::parse("").unwrap();

    // Run it for real first, both to create the indexes and to fix the
    // expected page.
    let query = StructuredQuery {
        from: vec![CollectionSelector { collection_id: "items".into(), all_descendants: false }],
        order_by: vec![order("n", true)],
        limit: Some(5),
        ..Default::default()
    };
    let page = run_query(&store, &db, &root, &query).await.unwrap();
    assert_eq!(page.len(), 5);

    // Now ask MongoDB how it ran it.
    let predicate = waldflam_engine::plan::plan(&[], &["n", "__name__"])
        .predicate
        .expect("ordering by a plain field requires it to exist");
    let mut filter = doc! { "collection_path": "items" };
    for (key, value) in predicate {
        filter.insert(key, value);
    }
    let sort = doc! {
        waldflam_engine::plan::sort_field("n"): 1,
        waldflam_engine::plan::sort_field("__name__"): 1,
    };

    let client = mongodb::Client::with_uri_str(&uri()).await.unwrap();
    let explain = client
        .database("waldflam")
        .run_command(doc! {
            "explain": {
                "find": format!("{}~{}", db.project_id, db.database_id),
                "filter": filter,
                "sort": sort,
                "limit": 5,
            },
            "verbosity": "executionStats",
        })
        .await
        .expect("explain");

    // Only the winning plan matters: `rejectedPlans` legitimately contains
    // the blocking-sort alternatives the planner considered and discarded.
    let winning = winning_plan(&explain);
    assert!(!winning.contains("SORT"), "ordering fell back to a blocking sort:\n{winning}");
    let examined = explain
        .get_document("executionStats")
        .and_then(|stats| stats.get_i32("totalDocsExamined").map(i64::from))
        .expect("executionStats.totalDocsExamined");
    assert!(examined <= 5, "index-ordered page examined {examined} documents for a limit of 5");
}

/// Being correct is not the point on its own — the predicate has to be served
/// by an index, otherwise this is a scan with extra steps.
#[tokio::test]
async fn filters_are_served_by_an_index_scan() {
    let store = store().await;
    let db = test_db("explain");
    seed(&store, &db, "items").await;
    let root = ResourcePath::parse("").unwrap();

    // Run one planned query so the indexes get created.
    let query = query_on("items", Some(field_filter("n", FieldOp::Equal, int(7))));
    let hits = run_query(&store, &db, &root, &query).await.unwrap();
    assert_eq!(hits.len(), 1, "exactly one document has n == 7");

    // Ask MongoDB how it would run the same predicate.
    let client = mongodb::Client::with_uri_str(&uri()).await.unwrap();
    let mongo = client.database("waldflam");
    let collection = format!("{}~{}", db.project_id, db.database_id);
    let predicate =
        waldflam_engine::plan::mongo_predicate(&[&FilterType::FieldFilter(FieldFilter {
            field: Some(FieldReference { field_path: "n".into() }),
            op: FieldOp::Equal as i32,
            value: Some(int(7)),
        })])
        .expect("equality on a plain field must be planned");

    let mut filter = doc! { "collection_path": "items" };
    for (key, value) in predicate {
        filter.insert(key, value);
    }
    let explain = mongo
        .run_command(doc! {
            "explain": { "find": &collection, "filter": filter },
            "verbosity": "executionStats",
        })
        .await
        .expect("explain");

    let winning = winning_plan(&explain);
    assert!(winning.contains("IXSCAN"), "predicate fell back to a collection scan:\n{winning}");
    assert!(!winning.contains("COLLSCAN"), "winning plan is a COLLSCAN:\n{winning}");

    let examined = explain
        .get_document("executionStats")
        .and_then(|stats| stats.get_i32("totalDocsExamined").map(i64::from))
        .expect("executionStats.totalDocsExamined");
    assert!(examined <= 2, "index scan examined {examined} documents for a single-match query");
}
