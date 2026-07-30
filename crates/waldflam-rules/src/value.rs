//! Rules runtime values.
//!
//! Int and float are distinct (int→float is the language's only coercion).
//! Errors are *values* (`Undefined`) that propagate, so `&&`/`||` can absorb
//! them — see `eval`.

use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Arc<str>),
    Bytes(Arc<[u8]>),
    /// Seconds + nanos since the epoch (UTC).
    Timestamp(i64, u32),
    /// Whole seconds + nanos.
    Duration(i64, u32),
    LatLng(f64, f64),
    List(Arc<Vec<Value>>),
    Map(Arc<BTreeMap<String, Value>>),
    /// Resolved path segments.
    Path(Arc<Vec<String>>),
    /// An error, carried as a value so `||`/`&&` can absorb it.
    Undefined(Arc<str>),
}

impl Value {
    pub fn str(s: impl Into<Arc<str>>) -> Self {
        Value::Str(s.into())
    }

    pub fn list(items: Vec<Value>) -> Self {
        Value::List(Arc::new(items))
    }

    pub fn map(entries: BTreeMap<String, Value>) -> Self {
        Value::Map(Arc::new(entries))
    }

    pub fn undefined(message: impl Into<Arc<str>>) -> Self {
        Value::Undefined(message.into())
    }

    pub fn is_undefined(&self) -> bool {
        matches!(self, Value::Undefined(_))
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// User-visible type name (`is` operator, error messages).
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "string",
            Value::Bytes(_) => "bytes",
            Value::Timestamp(..) => "timestamp",
            Value::Duration(..) => "duration",
            Value::LatLng(..) => "latlng",
            Value::List(_) => "list",
            Value::Map(_) => "map",
            Value::Path(_) => "path",
            Value::Undefined(_) => "undefined",
        }
    }

    pub fn matches_type(&self, ty: &str) -> bool {
        match ty {
            "number" => matches!(self, Value::Int(_) | Value::Float(_)),
            other => self.type_name() == other,
        }
    }

    /// Equality: same-type comparison; cross-type is `false`, not an error.
    /// int/float compare numerically; NaN never equals itself.
    pub fn equals(&self, other: &Value) -> bool {
        use Value::*;
        match (self, other) {
            (Null, Null) => true,
            (Bool(a), Bool(b)) => a == b,
            (Int(a), Int(b)) => a == b,
            (Float(a), Float(b)) => a == b,
            (Int(a), Float(b)) | (Float(b), Int(a)) => (*a as f64) == *b,
            (Str(a), Str(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (Timestamp(s1, n1), Timestamp(s2, n2)) => s1 == s2 && n1 == n2,
            (Duration(s1, n1), Duration(s2, n2)) => s1 == s2 && n1 == n2,
            (LatLng(a1, b1), LatLng(a2, b2)) => a1 == a2 && b1 == b2,
            (List(a), List(b)) => {
                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.equals(y))
            }
            (Map(a), Map(b)) => {
                a.len() == b.len()
                    && a.iter().zip(b.iter()).all(|((k1, v1), (k2, v2))| k1 == k2 && v1.equals(v2))
            }
            (Path(a), Path(b)) => a == b,
            _ => false,
        }
    }

    /// Ordering for `< <= > >=`; only same-category orderable types.
    pub fn compare(&self, other: &Value) -> Option<std::cmp::Ordering> {
        use Value::*;
        match (self, other) {
            (Int(a), Int(b)) => a.partial_cmp(b),
            (Float(a), Float(b)) => a.partial_cmp(b),
            (Int(a), Float(b)) => (*a as f64).partial_cmp(b),
            (Float(a), Int(b)) => a.partial_cmp(&(*b as f64)),
            (Str(a), Str(b)) => Some(a.as_ref().cmp(b.as_ref())),
            (Timestamp(s1, n1), Timestamp(s2, n2)) | (Duration(s1, n1), Duration(s2, n2)) => {
                Some(s1.cmp(s2).then(n1.cmp(n2)))
            }
            _ => None,
        }
    }
}
