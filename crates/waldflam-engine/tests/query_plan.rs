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
    CollectionSelector, FieldFilter, FieldReference, Filter, UnaryFilter,
};
use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::write::Operation;
use waldflam_proto::v1::{ArrayValue, Document, StructuredQuery, Value, Write};

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

    let rendered = explain.to_string();
    assert!(rendered.contains("IXSCAN"), "predicate fell back to a collection scan:\n{rendered}");
    assert!(!rendered.contains("COLLSCAN"), "plan still contains a COLLSCAN:\n{rendered}");

    let examined = explain
        .get_document("executionStats")
        .and_then(|stats| stats.get_i32("totalDocsExamined").map(i64::from))
        .expect("executionStats.totalDocsExamined");
    assert!(examined <= 2, "index scan examined {examined} documents for a single-match query");
}
