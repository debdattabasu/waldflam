//! Built-in functions and methods.
//!
//! Quirks preserved from the reference implementation (docs §7):
//! `matches()` is a *full* match on an RE2-compatible engine; timestamp
//! accessors are UTC and `seconds()` is second-of-minute while
//! `duration.seconds()` is the whole seconds field; `math.round` returns an
//! int while floor/ceil return floats.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::value::Value;

pub fn global(name: &str, args: &[Value]) -> Value {
    match (name, args) {
        ("int", [v]) => match v {
            Value::Int(_) => v.clone(),
            Value::Float(f) => Value::Int(*f as i64),
            Value::Str(s) => match s.parse::<i64>() {
                Ok(i) => Value::Int(i),
                Err(_) => Value::undefined("cannot convert string to int"),
            },
            Value::Bool(b) => Value::Int(*b as i64),
            other => Value::undefined(format!("cannot convert {} to int", other.type_name())),
        },
        ("float", [v]) => match v {
            Value::Float(_) => v.clone(),
            Value::Int(i) => Value::Float(*i as f64),
            Value::Str(s) => match s.parse::<f64>() {
                Ok(f) => Value::Float(f),
                Err(_) => Value::undefined("cannot convert string to float"),
            },
            other => Value::undefined(format!("cannot convert {} to float", other.type_name())),
        },
        ("string", [v]) => Value::str(match v {
            Value::Str(s) => return Value::Str(s.clone()),
            Value::Int(i) => i.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => "null".to_string(),
            Value::Path(p) => format!("/{}", p.join("/")),
            other => return Value::undefined(format!("cannot convert {} to string", other.type_name())),
        }),
        ("bool", [Value::Str(s)]) => match s.as_ref() {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => Value::undefined("cannot convert string to bool"),
        },
        ("path", [Value::Str(s)]) => Value::Path(Arc::new(
            s.trim_start_matches('/')
                .split('/')
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect(),
        )),
        ("math.abs", [v]) => match v {
            Value::Int(i) => match i.checked_abs() {
                Some(a) => Value::Int(a),
                None => Value::undefined("integer overflow"),
            },
            Value::Float(f) => Value::Float(f.abs()),
            _ => Value::undefined("math.abs expects a number"),
        },
        ("math.ceil", [v]) => float_fn(v, f64::ceil),
        ("math.floor", [v]) => float_fn(v, f64::floor),
        ("math.round", [v]) => match numeric(v) {
            Some(f) => Value::Int(f.round() as i64),
            None => Value::undefined("math.round expects a number"),
        },
        ("math.sqrt", [v]) => float_fn(v, f64::sqrt),
        ("math.pow", [a, b]) => match (numeric(a), numeric(b)) {
            (Some(a), Some(b)) => Value::Float(a.powf(b)),
            _ => Value::undefined("math.pow expects numbers"),
        },
        ("math.isNaN", [v]) => Value::Bool(matches!(v, Value::Float(f) if f.is_nan())),
        ("math.isInfinite", [v]) | ("math.isInfinity", [v]) => {
            Value::Bool(matches!(v, Value::Float(f) if f.is_infinite()))
        }
        ("duration.value", [Value::Int(n), Value::Str(unit)]) => {
            let seconds = match unit.as_ref() {
                "w" => n.checked_mul(604_800),
                "d" => n.checked_mul(86_400),
                "h" => n.checked_mul(3_600),
                "m" => n.checked_mul(60),
                "s" => Some(*n),
                "ms" => return Value::Duration(n.div_euclid(1_000), (n.rem_euclid(1_000) * 1_000_000) as u32),
                "ns" => return Value::Duration(n.div_euclid(1_000_000_000), n.rem_euclid(1_000_000_000) as u32),
                _ => return Value::undefined(format!("unknown duration unit {unit}")),
            };
            match seconds {
                Some(s) => Value::Duration(s, 0),
                None => Value::undefined("duration overflow"),
            }
        }
        ("duration.time", [Value::Int(h), Value::Int(m), Value::Int(s), Value::Int(ns)]) => {
            Value::Duration(h * 3600 + m * 60 + s, *ns as u32)
        }
        ("latlng.value", [a, b]) => match (numeric(a), numeric(b)) {
            (Some(lat), Some(lng)) if (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lng) => {
                Value::LatLng(lat, lng)
            }
            (Some(_), Some(_)) => Value::undefined("latlng out of range"),
            _ => Value::undefined("latlng.value expects numbers"),
        },
        ("timestamp.value", [Value::Int(ms)]) => {
            Value::Timestamp(ms.div_euclid(1_000), (ms.rem_euclid(1_000) * 1_000_000) as u32)
        }
        ("timestamp.date", [Value::Int(y), Value::Int(mo), Value::Int(d)]) => {
            match days_from_civil(*y, *mo, *d) {
                Some(days) => Value::Timestamp(days * 86_400, 0),
                None => Value::undefined("invalid date"),
            }
        }
        ("debug", [v]) => v.clone(),
        _ => Value::undefined(format!("function {name} is not defined")),
    }
}

pub fn method(recv: &Value, name: &str, args: &[Value]) -> Value {
    match (recv, name, args) {
        // ---- string ----
        (Value::Str(s), "size", []) => Value::Int(s.chars().count() as i64),
        (Value::Str(s), "lower", []) => Value::str(s.to_lowercase()),
        (Value::Str(s), "upper", []) => Value::str(s.to_uppercase()),
        (Value::Str(s), "trim", []) => Value::str(s.trim().to_string()),
        (Value::Str(s), "split", [Value::Str(re)]) => match regex::Regex::new(re) {
            Ok(re) => Value::list(re.split(s).map(|p| Value::str(p.to_string())).collect()),
            Err(_) => Value::undefined("invalid regular expression"),
        },
        (Value::Str(s), "matches", [Value::Str(pattern)]) => {
            // Rules `matches` is a FULL match.
            match regex::Regex::new(&format!("^(?:{pattern})$")) {
                Ok(re) => Value::Bool(re.is_match(s)),
                Err(_) => Value::undefined("invalid regular expression"),
            }
        }
        (Value::Str(s), "replace", [Value::Str(pattern), Value::Str(to)]) => {
            match regex::Regex::new(pattern) {
                Ok(re) => Value::str(re.replace_all(s, to.as_ref()).into_owned()),
                Err(_) => Value::undefined("invalid regular expression"),
            }
        }
        (Value::Str(s), "toUtf8", []) => Value::Bytes(Arc::from(s.as_bytes())),

        // ---- bytes ----
        (Value::Bytes(b), "size", []) => Value::Int(b.len() as i64),
        (Value::Bytes(b), "toBase64", []) => Value::str(base64_encode(b)),

        // ---- list ----
        (Value::List(items), "size", []) => Value::Int(items.len() as i64),
        (Value::List(items), "hasAll", [Value::List(other)]) => {
            Value::Bool(other.iter().all(|o| items.iter().any(|i| i.equals(o))))
        }
        (Value::List(items), "hasAny", [Value::List(other)]) => {
            Value::Bool(other.iter().any(|o| items.iter().any(|i| i.equals(o))))
        }
        (Value::List(items), "hasOnly", [Value::List(other)]) => {
            Value::Bool(items.iter().all(|i| other.iter().any(|o| o.equals(i))))
        }
        (Value::List(items), "join", [Value::Str(sep)]) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items.iter() {
                match item {
                    Value::Str(s) => parts.push(s.to_string()),
                    _ => return Value::undefined("join requires a list of strings"),
                }
            }
            Value::str(parts.join(sep))
        }
        (Value::List(items), "concat", [Value::List(other)]) => {
            let mut out = items.as_ref().clone();
            out.extend(other.iter().cloned());
            Value::list(out)
        }
        (Value::List(items), "removeAll", [Value::List(other)]) => Value::list(
            items
                .iter()
                .filter(|i| !other.iter().any(|o| o.equals(i)))
                .cloned()
                .collect(),
        ),
        (Value::List(items), "toSet", []) => {
            let mut out: Vec<Value> = Vec::new();
            for item in items.iter() {
                if !out.iter().any(|o| o.equals(item)) {
                    out.push(item.clone());
                }
            }
            Value::list(out)
        }

        // ---- map ----
        (Value::Map(m), "size", []) => Value::Int(m.len() as i64),
        (Value::Map(m), "keys", []) => {
            Value::list(m.keys().map(|k| Value::str(k.as_str())).collect())
        }
        (Value::Map(m), "values", []) => Value::list(m.values().cloned().collect()),
        (Value::Map(m), "get", [key, default]) => match key {
            Value::Str(k) => m.get(k.as_ref()).cloned().unwrap_or_else(|| default.clone()),
            _ => Value::undefined("map.get expects a string key"),
        },
        (Value::Map(a), "diff", [Value::Map(b)]) => {
            // MapDiff surfaced as a map of changed-key lists.
            let mut affected: Vec<Value> = Vec::new();
            let mut added = Vec::new();
            let mut removed = Vec::new();
            let mut changed = Vec::new();
            for (k, v) in a.iter() {
                match b.get(k) {
                    None => {
                        removed.push(Value::str(k.as_str()));
                        affected.push(Value::str(k.as_str()));
                    }
                    Some(other) if !v.equals(other) => {
                        changed.push(Value::str(k.as_str()));
                        affected.push(Value::str(k.as_str()));
                    }
                    _ => {}
                }
            }
            for k in b.keys() {
                if !a.contains_key(k) {
                    added.push(Value::str(k.as_str()));
                    affected.push(Value::str(k.as_str()));
                }
            }
            let mut out = BTreeMap::new();
            out.insert("addedKeys".into(), Value::list(added));
            out.insert("removedKeys".into(), Value::list(removed));
            out.insert("changedKeys".into(), Value::list(changed));
            out.insert("affectedKeys".into(), Value::list(affected));
            Value::map(out)
        }
        // MapDiff result methods.
        (Value::Map(m), "addedKeys" | "removedKeys" | "changedKeys" | "affectedKeys", [])
            if m.contains_key("affectedKeys") =>
        {
            m.get(name).cloned().unwrap_or_else(|| Value::list(Vec::new()))
        }

        // ---- path ----
        (Value::Path(p), "size", []) => Value::Int(p.len() as i64),
        (Value::Path(p), "bind", [Value::Map(bindings)]) => Value::Path(Arc::new(
            p.iter()
                .map(|seg| match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                    Some(key) => match bindings.get(key) {
                        Some(Value::Str(v)) => v.to_string(),
                        _ => seg.clone(),
                    },
                    None => seg.clone(),
                })
                .collect(),
        )),

        // ---- timestamp (UTC) ----
        (Value::Timestamp(s, n), _, []) => timestamp_method(*s, *n, name),
        // ---- duration ----
        (Value::Duration(s, n), "seconds", []) => Value::Int(*s),
        (Value::Duration(_, n), "nanos", []) => Value::Int(*n as i64),

        // ---- latlng ----
        (Value::LatLng(lat, _), "latitude", []) => Value::Float(*lat),
        (Value::LatLng(_, lng), "longitude", []) => Value::Float(*lng),
        (Value::LatLng(lat1, lng1), "distance", [Value::LatLng(lat2, lng2)]) => {
            const R: f64 = 6_371_009.0;
            let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
            let (dp, dl) = ((lat2 - lat1).to_radians(), (lng2 - lng1).to_radians());
            let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
            Value::Float(2.0 * R * a.sqrt().asin())
        }

        _ => Value::undefined(format!(
            "method {name} is not defined on {}",
            recv.type_name()
        )),
    }
}

fn timestamp_method(seconds: i64, nanos: u32, name: &str) -> Value {
    let days = seconds.div_euclid(86_400);
    let secs_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    match name {
        "seconds" => Value::Int(secs_of_day % 60),
        "minutes" => Value::Int((secs_of_day / 60) % 60),
        "hours" => Value::Int(secs_of_day / 3600),
        "nanos" => Value::Int(nanos as i64),
        "year" => Value::Int(year),
        "month" => Value::Int(month),
        "day" => Value::Int(day),
        // 1970-01-01 was a Thursday (=4 in Mon=1..Sun=7).
        "dayOfWeek" => Value::Int((days + 3).rem_euclid(7) + 1),
        "dayOfYear" => {
            let jan1 = days_from_civil(year, 1, 1).unwrap_or(0);
            Value::Int(days - jan1 + 1)
        }
        "date" => Value::Timestamp(days * 86_400, 0),
        "time" => Value::Duration(secs_of_day, nanos),
        "toMillis" => Value::Int(seconds * 1000 + (nanos / 1_000_000) as i64),
        _ => Value::undefined(format!("method {name} is not defined on timestamp")),
    }
}

fn float_fn(v: &Value, f: fn(f64) -> f64) -> Value {
    match numeric(v) {
        Some(x) => Value::Float(f(x)),
        None => Value::undefined("expected a number"),
    }
}

fn numeric(v: &Value) -> Option<f64> {
    match v {
        Value::Int(i) => Some(*i as f64),
        Value::Float(f) => Some(*f),
        _ => None,
    }
}

/// Howard Hinnant's civil-date algorithms (days since 1970-01-01).
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    if !(1..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}
