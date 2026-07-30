//! Firestore's total order over values.
//!
//! The server must sort exactly like the client-side comparators (the Go
//! SDK's `order.go` states the same order), or watch snapshots and cursors
//! break. Cross-type rank, then per-type comparison.

use std::cmp::Ordering;

use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::{ArrayValue, MapValue, Value};

/// Cross-type rank. Gaps in the numbering are the BSON-compat sentinel types
/// (MinKey, BsonTimestamp, BsonBinary, ObjectId, Regex, MaxKey) which we
/// don't support yet; when added they slot between the existing ranks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TypeRank {
    Null = 0,
    Boolean = 2,
    Number = 3,
    Timestamp = 4,
    String = 6,
    Bytes = 7,
    Reference = 9,
    GeoPoint = 11,
    Array = 13,
    Vector = 14,
    Map = 15,
}

fn rank(v: &Value) -> TypeRank {
    match &v.value_type {
        None | Some(ValueType::NullValue(_)) => TypeRank::Null,
        Some(ValueType::BooleanValue(_)) => TypeRank::Boolean,
        Some(ValueType::IntegerValue(_)) | Some(ValueType::DoubleValue(_)) => TypeRank::Number,
        Some(ValueType::TimestampValue(_)) => TypeRank::Timestamp,
        Some(ValueType::StringValue(_)) => TypeRank::String,
        Some(ValueType::BytesValue(_)) => TypeRank::Bytes,
        Some(ValueType::ReferenceValue(_)) => TypeRank::Reference,
        Some(ValueType::GeoPointValue(_)) => TypeRank::GeoPoint,
        Some(ValueType::ArrayValue(_)) => TypeRank::Array,
        Some(ValueType::MapValue(m)) => {
            if vector_values(m).is_some() {
                TypeRank::Vector
            } else {
                TypeRank::Map
            }
        }
        // Pipeline expression values (field/variable references, functions)
        // are not storable document data and never reach ordering.
        Some(_) => TypeRank::Map,
    }
}

/// Detects the vector sentinel shape `{"__type__": "__vector__", "value": [...]}`.
fn vector_values(m: &MapValue) -> Option<&ArrayValue> {
    match m.fields.get("__type__")?.value_type.as_ref()? {
        ValueType::StringValue(s) if s == "__vector__" => {}
        _ => return None,
    }
    match m.fields.get("value")?.value_type.as_ref()? {
        ValueType::ArrayValue(a) => Some(a),
        _ => None,
    }
}

/// Whether two values share a type rank (int and double share Number) —
/// the "same category" test behind type-bounded inequality filters.
pub fn same_type_rank(a: &Value, b: &Value) -> bool {
    rank(a) == rank(b)
}

/// Total order over Firestore values.
pub fn compare_values(a: &Value, b: &Value) -> Ordering {
    let (ra, rb) = (rank(a), rank(b));
    if ra != rb {
        return ra.cmp(&rb);
    }
    match (a.value_type.as_ref(), b.value_type.as_ref()) {
        (None | Some(ValueType::NullValue(_)), _) => Ordering::Equal,
        (Some(ValueType::BooleanValue(x)), Some(ValueType::BooleanValue(y))) => x.cmp(y),
        (Some(ValueType::IntegerValue(x)), Some(ValueType::IntegerValue(y))) => x.cmp(y),
        (Some(ValueType::DoubleValue(x)), Some(ValueType::DoubleValue(y))) => cmp_doubles(*x, *y),
        (Some(ValueType::IntegerValue(x)), Some(ValueType::DoubleValue(y))) => {
            cmp_int_double(*x, *y)
        }
        (Some(ValueType::DoubleValue(x)), Some(ValueType::IntegerValue(y))) => {
            cmp_int_double(*y, *x).reverse()
        }
        (Some(ValueType::TimestampValue(x)), Some(ValueType::TimestampValue(y))) => {
            x.seconds.cmp(&y.seconds).then(x.nanos.cmp(&y.nanos))
        }
        (Some(ValueType::StringValue(x)), Some(ValueType::StringValue(y))) => x.cmp(y),
        (Some(ValueType::BytesValue(x)), Some(ValueType::BytesValue(y))) => x.cmp(y),
        (Some(ValueType::ReferenceValue(x)), Some(ValueType::ReferenceValue(y))) => {
            cmp_references(x, y)
        }
        (Some(ValueType::GeoPointValue(x)), Some(ValueType::GeoPointValue(y))) => {
            cmp_doubles(x.latitude, y.latitude).then(cmp_doubles(x.longitude, y.longitude))
        }
        (Some(ValueType::ArrayValue(x)), Some(ValueType::ArrayValue(y))) => {
            cmp_value_slices(&x.values, &y.values)
        }
        (Some(ValueType::MapValue(x)), Some(ValueType::MapValue(y))) => {
            match (vector_values(x), vector_values(y)) {
                // Vectors: dimension first, then lexicographic.
                (Some(vx), Some(vy)) => vx
                    .values
                    .len()
                    .cmp(&vy.values.len())
                    .then_with(|| cmp_value_slices(&vx.values, &vy.values)),
                _ => cmp_maps(x, y),
            }
        }
        // Same rank but different shapes: only reachable via non-storable
        // pipeline expression values; don't panic the server over them.
        _ => Ordering::Equal,
    }
}

/// Doubles with a total order: NaN sorts below everything (all NaNs equal),
/// and -0.0 == 0.0.
fn cmp_doubles(x: f64, y: f64) -> Ordering {
    match (x.is_nan(), y.is_nan()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => x.partial_cmp(&y).expect("non-NaN doubles compare"),
    }
}

/// Exact i64 vs f64 comparison — casting the i64 to f64 would lose precision
/// above 2^53.
fn cmp_int_double(i: i64, d: f64) -> Ordering {
    const TWO_63: f64 = 9_223_372_036_854_775_808.0; // 2^63, exactly representable
    if d.is_nan() {
        return Ordering::Greater;
    }
    if d >= TWO_63 {
        return Ordering::Less;
    }
    if d < -TWO_63 {
        return Ordering::Greater;
    }
    // d.trunc() is integral and within [-2^63, 2^63), so the cast is exact.
    let t = d.trunc() as i64;
    i.cmp(&t).then_with(|| {
        let fract = d - t as f64;
        // i == trunc(d): the fractional part (sign matches d) breaks the tie.
        cmp_doubles(0.0, fract)
    })
}

/// References compare path-segment-wise, not as flat strings.
fn cmp_references(x: &str, y: &str) -> Ordering {
    let (mut xs, mut ys) = (x.split('/'), y.split('/'));
    loop {
        match (xs.next(), ys.next()) {
            (Some(a), Some(b)) => match a.cmp(b) {
                Ordering::Equal => continue,
                other => return other,
            },
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
        }
    }
}

fn cmp_value_slices(x: &[Value], y: &[Value]) -> Ordering {
    for (a, b) in x.iter().zip(y.iter()) {
        match compare_values(a, b) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    x.len().cmp(&y.len())
}

/// Maps compare by sorted key order: pairwise key then value, then size.
fn cmp_maps(x: &MapValue, y: &MapValue) -> Ordering {
    let mut xk: Vec<&String> = x.fields.keys().collect();
    let mut yk: Vec<&String> = y.fields.keys().collect();
    xk.sort_unstable();
    yk.sort_unstable();
    for (ka, kb) in xk.iter().zip(yk.iter()) {
        match ka.cmp(kb) {
            Ordering::Equal => {}
            other => return other,
        }
        match compare_values(&x.fields[*ka], &y.fields[*kb]) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    xk.len().cmp(&yk.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use waldflam_proto::google::r#type::LatLng;

    fn null() -> Value {
        Value { value_type: Some(ValueType::NullValue(0)) }
    }
    fn boolean(b: bool) -> Value {
        Value { value_type: Some(ValueType::BooleanValue(b)) }
    }
    fn int(i: i64) -> Value {
        Value { value_type: Some(ValueType::IntegerValue(i)) }
    }
    fn double(d: f64) -> Value {
        Value { value_type: Some(ValueType::DoubleValue(d)) }
    }
    fn ts(seconds: i64, nanos: i32) -> Value {
        Value {
            value_type: Some(ValueType::TimestampValue(prost_types::Timestamp { seconds, nanos })),
        }
    }
    fn string(s: &str) -> Value {
        Value { value_type: Some(ValueType::StringValue(s.into())) }
    }
    fn bytes(b: &[u8]) -> Value {
        Value { value_type: Some(ValueType::BytesValue(b.to_vec())) }
    }
    fn reference(r: &str) -> Value {
        Value { value_type: Some(ValueType::ReferenceValue(r.into())) }
    }
    fn geo(lat: f64, lng: f64) -> Value {
        Value {
            value_type: Some(ValueType::GeoPointValue(LatLng { latitude: lat, longitude: lng })),
        }
    }
    fn array(vs: Vec<Value>) -> Value {
        Value { value_type: Some(ValueType::ArrayValue(ArrayValue { values: vs })) }
    }
    fn map(entries: Vec<(&str, Value)>) -> Value {
        Value {
            value_type: Some(ValueType::MapValue(MapValue {
                fields: entries.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
            })),
        }
    }
    fn vector(ds: Vec<f64>) -> Value {
        map(vec![
            ("__type__", string("__vector__")),
            ("value", array(ds.into_iter().map(double).collect())),
        ])
    }

    /// Asserts the slice is in strictly ascending groups: values in the same
    /// inner vec are equal, later groups are greater.
    fn assert_ascending(groups: Vec<Vec<Value>>) {
        for (gi, group) in groups.iter().enumerate() {
            for a in group {
                for b in group {
                    assert_eq!(compare_values(a, b), Ordering::Equal, "{a:?} != {b:?}");
                }
                for later in &groups[gi + 1..] {
                    for b in later {
                        assert_eq!(compare_values(a, b), Ordering::Less, "{a:?} !< {b:?}");
                        assert_eq!(compare_values(b, a), Ordering::Greater, "{b:?} !> {a:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn total_order_matrix() {
        assert_ascending(vec![
            vec![null()],
            vec![boolean(false)],
            vec![boolean(true)],
            vec![double(f64::NAN)],
            vec![double(f64::NEG_INFINITY)],
            vec![int(i64::MIN)],
            vec![double(-1.1)],
            vec![int(-1), double(-1.0)],
            vec![int(0), double(0.0), double(-0.0)],
            vec![double(f64::MIN_POSITIVE)],
            vec![int(1), double(1.0)],
            vec![double(1.1)],
            vec![int(42)],
            // 2^53 + 1 is not representable as f64; the int is strictly larger
            // than the double it would round to... but 2^53 as double equals it.
            vec![int(1 << 53), double((1u64 << 53) as f64)],
            vec![int((1 << 53) + 1)],
            vec![int(i64::MAX)],
            vec![double(1e300)],
            vec![double(f64::INFINITY)],
            vec![ts(0, 0)],
            vec![ts(0, 1)],
            vec![ts(1, 0)],
            vec![string("")],
            vec![string("a")],
            vec![string("a\u{0000}")],
            vec![string("b")],
            vec![string("\u{00e9}")], // é > ascii by UTF-8 bytes
            vec![bytes(b"")],
            vec![bytes(b"\x00")],
            vec![bytes(b"\xff")],
            vec![reference("projects/p/databases/d/documents/c/d")],
            vec![reference("projects/p/databases/d/documents/c/d/sub/x")],
            vec![reference("projects/p/databases/d/documents/c/d2")],
            vec![geo(-90.0, 0.0)],
            vec![geo(0.0, -1.0)],
            vec![geo(0.0, 1.0)],
            vec![geo(1.0, 0.0)],
            vec![array(vec![])],
            vec![array(vec![int(1)])],
            vec![array(vec![int(1), int(2)])],
            vec![array(vec![int(2)])],
            vec![vector(vec![100.0])],
            vec![vector(vec![1.0, 2.0])],
            vec![vector(vec![1.0, 3.0])],
            vec![map(vec![])],
            vec![map(vec![("a", int(1))])],
            vec![map(vec![("a", int(1)), ("b", int(1))])],
            vec![map(vec![("a", int(2))])],
            vec![map(vec![("b", int(0))])],
        ]);
    }

    #[test]
    fn segment_wise_reference_order() {
        // Flat string compare would put "c/d/sub" before "c/d2" wrong when a
        // segment is a prefix of another ('/' = 0x2f < '2' = 0x32 makes flat
        // agree here, but ':' or '!' suffixed ids would flip it). Verify the
        // segment rule directly.
        assert_eq!(
            cmp_references(
                "projects/p/databases/d/documents/c/d!",
                "projects/p/databases/d/documents/c/d/x/y"
            ),
            Ordering::Greater // "d!" > "d" segment-wise even though '!' < '/'
        );
    }

    #[test]
    fn int_double_precision_edges() {
        assert_eq!(cmp_int_double(1, 1.5), Ordering::Less);
        assert_eq!(cmp_int_double(2, 1.5), Ordering::Greater);
        assert_eq!(cmp_int_double(-1, -0.5), Ordering::Less);
        assert_eq!(cmp_int_double(0, -0.5), Ordering::Greater);
        assert_eq!(cmp_int_double(i64::MAX, 9.3e18), Ordering::Less);
        assert_eq!(cmp_int_double(i64::MIN, -9.3e18), Ordering::Greater);
        assert_eq!(cmp_int_double(i64::MIN, -9_223_372_036_854_775_808.0), Ordering::Equal);
        assert_eq!(cmp_int_double(100, f64::NAN), Ordering::Greater);
    }
}
