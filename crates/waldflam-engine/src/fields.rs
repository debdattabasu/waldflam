//! Dotted field-path access into a document's field map.
//!
//! TODO(field-paths): support backtick-quoted segments; plain dots for now.

use std::collections::HashMap;

use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::{MapValue, Value};

pub fn split_path(path: &str) -> Vec<&str> {
    path.split('.').collect()
}

pub fn get_field<'a>(fields: &'a HashMap<String, Value>, path: &str) -> Option<&'a Value> {
    let mut segments = split_path(path).into_iter();
    let mut current = fields.get(segments.next()?)?;
    for seg in segments {
        match current.value_type.as_ref()? {
            ValueType::MapValue(m) => current = m.fields.get(seg)?,
            _ => return None,
        }
    }
    Some(current)
}

/// Sets `path` to `value`, creating intermediate maps (and replacing
/// non-map intermediates, matching Firestore merge semantics).
pub fn set_field(fields: &mut HashMap<String, Value>, path: &str, value: Value) {
    let segments = split_path(path);
    let (last, parents) = segments.split_last().expect("non-empty path");
    let mut current = fields;
    for seg in parents {
        let entry = current
            .entry((*seg).to_owned())
            .or_insert_with(|| map_value(HashMap::new()));
        if !matches!(entry.value_type, Some(ValueType::MapValue(_))) {
            *entry = map_value(HashMap::new());
        }
        let Some(ValueType::MapValue(m)) = entry.value_type.as_mut() else {
            unreachable!("just ensured a map");
        };
        current = &mut m.fields;
    }
    current.insert((*last).to_owned(), value);
}

pub fn delete_field(fields: &mut HashMap<String, Value>, path: &str) {
    let segments = split_path(path);
    let (last, parents) = segments.split_last().expect("non-empty path");
    let mut current = fields;
    for seg in parents {
        match current.get_mut(*seg).and_then(|v| v.value_type.as_mut()) {
            Some(ValueType::MapValue(m)) => current = &mut m.fields,
            _ => return, // path doesn't exist; nothing to delete
        }
    }
    current.remove(*last);
}

pub fn map_value(fields: HashMap<String, Value>) -> Value {
    Value { value_type: Some(ValueType::MapValue(MapValue { fields })) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(i: i64) -> Value {
        Value { value_type: Some(ValueType::IntegerValue(i)) }
    }

    #[test]
    fn nested_set_get_delete() {
        let mut fields = HashMap::new();
        set_field(&mut fields, "a.b.c", int(1));
        set_field(&mut fields, "a.b.d", int(2));
        set_field(&mut fields, "top", int(3));
        assert_eq!(get_field(&fields, "a.b.c"), Some(&int(1)));
        assert_eq!(get_field(&fields, "a.b.d"), Some(&int(2)));
        assert_eq!(get_field(&fields, "top"), Some(&int(3)));
        assert_eq!(get_field(&fields, "a.b"), Some(&map_value(
            [("c".to_owned(), int(1)), ("d".to_owned(), int(2))].into_iter().collect(),
        )));
        assert_eq!(get_field(&fields, "a.missing"), None);
        assert_eq!(get_field(&fields, "top.not_a_map"), None);

        // Setting through a non-map replaces it with a map.
        set_field(&mut fields, "top.now_map", int(4));
        assert_eq!(get_field(&fields, "top.now_map"), Some(&int(4)));

        delete_field(&mut fields, "a.b.c");
        assert_eq!(get_field(&fields, "a.b.c"), None);
        assert_eq!(get_field(&fields, "a.b.d"), Some(&int(2)));
        delete_field(&mut fields, "missing.x"); // no-op
    }
}
