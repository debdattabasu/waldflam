//! Order-preserving encoding of whole Firestore values into index keys.
//!
//! `encode_value` produces self-delimiting bytes whose unsigned lexicographic
//! order equals `order::compare_values` for every pair of values, so composite
//! index keys are plain concatenations. Keys are stored in MongoDB as
//! lowercase-hex BSON strings (`to_index_string`) because BSON compares
//! Binary by *length first*, which would break variable-length keys, while
//! strings compare byte-wise.
//!
//! Layout per value: a type-rank tag byte, then a type-specific payload.
//! Tag numbering leaves gaps for the BSON-compat sentinel types (MinKey,
//! BsonTimestamp, BsonBinary, ObjectId, Regex, MaxKey) and for the ABSENT
//! scan bound, mirroring the rank spacing in `order::TypeRank`.
//!
//! TODO(index-truncation): production Firestore truncates index values at
//! 1500 bytes with a truncated-flag tiebreaker; add when large-value support
//! lands.

use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::{MapValue, Value};

use crate::encoding::{encode_f64, encode_i64, encode_number, NumberParts};

/// Sorts below every real value: the lower scan bound for "field exists".
pub const TAG_ABSENT: u8 = 0x04;
const TAG_NULL: u8 = 0x08;
const TAG_BOOLEAN: u8 = 0x10;
const TAG_NUMBER: u8 = 0x18;
const TAG_TIMESTAMP: u8 = 0x20;
const TAG_STRING: u8 = 0x28;
const TAG_BYTES: u8 = 0x30;
const TAG_REFERENCE: u8 = 0x38;
const TAG_GEO_POINT: u8 = 0x40;
const TAG_ARRAY: u8 = 0x48;
const TAG_VECTOR: u8 = 0x50;
const TAG_MAP: u8 = 0x58;
/// Sorts above every real value: the upper scan bound.
pub const TAG_MAX: u8 = 0xF8;

/// Markers inside variable-length containers: `ITEM` before each element,
/// `END` after the last. `END < ITEM` makes a prefix sort before its
/// extensions, and `ITEM` shields elements whose first byte is a low tag.
const END: u8 = 0x00;
const ITEM: u8 = 0x01;

pub fn encode_value(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(&mut out, value);
    out
}

/// Hex-encodes an index key for storage as a BSON string; lowercase hex is
/// monotone in ASCII, so string order equals byte order.
pub fn to_index_string(key: &[u8]) -> String {
    let mut s = String::with_capacity(key.len() * 2);
    for b in key {
        use std::fmt::Write;
        write!(s, "{b:02x}").expect("write to string");
    }
    s
}

fn write_value(out: &mut Vec<u8>, value: &Value) {
    match value.value_type.as_ref() {
        None | Some(ValueType::NullValue(_)) => out.push(TAG_NULL),
        Some(ValueType::BooleanValue(b)) => {
            out.push(TAG_BOOLEAN);
            out.push(*b as u8);
        }
        Some(ValueType::IntegerValue(i)) => {
            out.push(TAG_NUMBER);
            out.extend_from_slice(&encode_i64(*i));
        }
        Some(ValueType::DoubleValue(d)) => {
            out.push(TAG_NUMBER);
            out.extend_from_slice(&encode_f64(*d));
        }
        Some(ValueType::TimestampValue(ts)) => {
            out.push(TAG_TIMESTAMP);
            // Offset-binary big-endian: order-preserving and fixed-width
            // (nanos are validated to [0, 1e9)).
            out.extend_from_slice(&((ts.seconds as u64) ^ (1 << 63)).to_be_bytes());
            out.extend_from_slice(&(ts.nanos as u32).to_be_bytes());
        }
        Some(ValueType::StringValue(s)) => {
            out.push(TAG_STRING);
            write_escaped(out, s.as_bytes());
        }
        Some(ValueType::BytesValue(b)) => {
            out.push(TAG_BYTES);
            write_escaped(out, b);
        }
        Some(ValueType::ReferenceValue(r)) => {
            out.push(TAG_REFERENCE);
            // Segment-wise: each segment is an ITEM so "c/d!" sorts after
            // "c/d/x" (segment compare), unlike flat string order.
            for segment in r.split('/') {
                out.push(ITEM);
                write_escaped(out, segment.as_bytes());
            }
            out.push(END);
        }
        Some(ValueType::GeoPointValue(g)) => {
            out.push(TAG_GEO_POINT);
            out.extend_from_slice(&encode_f64(g.latitude));
            out.extend_from_slice(&encode_f64(g.longitude));
        }
        Some(ValueType::ArrayValue(a)) => {
            out.push(TAG_ARRAY);
            for v in &a.values {
                out.push(ITEM);
                write_value(out, v);
            }
            out.push(END);
        }
        Some(ValueType::MapValue(m)) => match vector_values(m) {
            Some(elements) => {
                out.push(TAG_VECTOR);
                // Dimension first, then elements.
                out.extend_from_slice(&encode_i64(elements.len() as i64));
                for v in elements {
                    write_value(out, v);
                }
            }
            None => {
                out.push(TAG_MAP);
                let mut keys: Vec<&String> = m.fields.keys().collect();
                keys.sort_unstable();
                for k in keys {
                    out.push(ITEM);
                    write_escaped(out, k.as_bytes());
                    write_value(out, &m.fields[k]);
                }
                out.push(END);
            }
        },
        // Pipeline expression values are not storable document data.
        Some(_) => out.push(TAG_MAP),
    }
}

/// Terminated byte escape: `0x00` in content becomes `0x00 0xFF`, and a bare
/// `0x00` terminates. Preserves order because `0xFF` is the maximum byte and
/// the terminator the minimum, so a prefix sorts before its extensions.
fn write_escaped(out: &mut Vec<u8>, bytes: &[u8]) {
    for &b in bytes {
        out.push(b);
        if b == 0x00 {
            out.push(0xFF);
        }
    }
    out.push(0x00);
}

fn vector_values(m: &MapValue) -> Option<&[Value]> {
    match m.fields.get("__type__")?.value_type.as_ref()? {
        ValueType::StringValue(s) if s == "__vector__" => {}
        _ => return None,
    }
    match m.fields.get("value")?.value_type.as_ref()? {
        ValueType::ArrayValue(a) => Some(&a.values),
        _ => None,
    }
}

/// Numbers appearing outside `Value` context (e.g. composite-key parts).
pub fn encode_number_key(parts: NumberParts) -> Vec<u8> {
    let mut out = vec![TAG_NUMBER];
    out.extend_from_slice(&encode_number(parts));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    use prost_types::Timestamp;
    use waldflam_proto::google::r#type::LatLng;
    use waldflam_proto::v1::ArrayValue;

    use crate::order::compare_values;

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
        Value { value_type: Some(ValueType::TimestampValue(Timestamp { seconds, nanos })) }
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

    fn corpus() -> Vec<Value> {
        vec![
            null(),
            boolean(false),
            boolean(true),
            double(f64::NAN),
            double(f64::NEG_INFINITY),
            int(i64::MIN),
            double(-1.5),
            int(-1),
            double(-0.0),
            int(0),
            double(0.5),
            int(1),
            double(1.0),
            int(42),
            int(1 << 53),
            double((1u64 << 53) as f64),
            int((1 << 53) + 1),
            int(i64::MAX),
            double(f64::INFINITY),
            ts(-100, 0),
            ts(0, 0),
            ts(0, 1),
            ts(1, 999_999_999),
            string(""),
            string("a"),
            string("a\u{0000}"),
            string("a\u{0000}b"),
            string("a!"),
            string("ab"),
            string("b"),
            string("\u{00e9}"),
            bytes(b""),
            bytes(b"\x00"),
            bytes(b"\x00\xff"),
            bytes(b"a"),
            bytes(b"\xff"),
            reference("projects/p/databases/d/documents/c/d"),
            reference("projects/p/databases/d/documents/c/d/x/y"),
            reference("projects/p/databases/d/documents/c/d!"),
            reference("projects/p/databases/d/documents/c/d2"),
            geo(-90.0, -180.0),
            geo(0.0, -1.0),
            geo(0.0, 1.0),
            geo(1.0, 0.0),
            array(vec![]),
            array(vec![null()]),
            array(vec![int(1)]),
            array(vec![int(1), int(2)]),
            array(vec![int(2)]),
            array(vec![string("a")]),
            vector(vec![100.0]),
            vector(vec![1.0, 2.0]),
            vector(vec![1.0, 3.0]),
            map(vec![]),
            map(vec![("a", null())]),
            map(vec![("a", int(1))]),
            map(vec![("a", int(1)), ("b", int(1))]),
            map(vec![("a", int(2))]),
            map(vec![("a\u{0000}", int(0))]),
            map(vec![("b", int(0))]),
            map(vec![("nested", map(vec![("x", array(vec![int(1), string("y")]))]))]),
        ]
    }

    /// Byte order (and hex-string order) must equal semantic value order for
    /// every pair in the corpus.
    #[test]
    fn key_order_matches_value_order() {
        let values = corpus();
        let keys: Vec<Vec<u8>> = values.iter().map(encode_value).collect();
        let hex: Vec<String> = keys.iter().map(|k| to_index_string(k)).collect();
        for (i, a) in values.iter().enumerate() {
            for (j, b) in values.iter().enumerate() {
                let semantic = compare_values(a, b);
                assert_eq!(semantic, keys[i].cmp(&keys[j]), "{a:?} vs {b:?}");
                assert_eq!(semantic, hex[i].cmp(&hex[j]), "hex: {a:?} vs {b:?}");
                if semantic == Ordering::Equal {
                    assert_eq!(keys[i], keys[j], "{a:?} vs {b:?}");
                }
            }
        }
    }

    /// Concatenated keys (composite indexes) compare component-wise because
    /// every encoding is self-delimiting and prefix-free.
    #[test]
    fn composite_keys_compare_component_wise() {
        let pairs = [
            (string("a"), int(2)),
            (string("a"), int(10)),
            (string("a!"), int(1)),
            (string("ab"), int(0)),
            (string("b"), int(-5)),
        ];
        let composite: Vec<Vec<u8>> = pairs
            .iter()
            .map(|(x, y)| {
                let mut k = encode_value(x);
                k.extend_from_slice(&encode_value(y));
                k
            })
            .collect();
        for w in composite.windows(2) {
            assert!(w[0] < w[1], "{:02x?} !< {:02x?}", w[0], w[1]);
        }
    }

    #[test]
    fn scan_bounds_bracket_all_values() {
        for v in corpus() {
            let key = encode_value(&v);
            assert!(key[0] > TAG_ABSENT, "{v:?}");
            assert!(key[0] < TAG_MAX, "{v:?}");
        }
    }
}
