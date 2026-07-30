//! The evaluator: error-as-value propagation with `&&`/`||` absorption,
//! evaluation budgets, and the standard library.
//!
//! Absorption table (docs/architecture.md §7):
//!   `true || <err>`  → true    (short circuit, rhs never runs)
//!   `false && <err>` → false   (short circuit)
//!   `<err> || true`  → true    (absorbed)
//!   `<err> && false` → false   (absorbed)
//!   `<err> || false` / `<err> && true` / `false || <err>` / `true && <err>`
//!                    → error

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::ast::*;
use crate::value::Value;

const MAX_STEPS: u32 = 10_000;
const MAX_CALL_DEPTH: u32 = 20;

/// What the host (Firestore binding) must provide.
pub trait Host {
    /// `get()` / `getAfter()`: document data as a map, or None if missing.
    fn get_document(&mut self, path: &[String], after: bool) -> Result<Option<Value>, String>;
    /// `exists()` / `existsAfter()`.
    fn exists(&mut self, path: &[String], after: bool) -> Result<bool, String>;
}

pub struct Budget {
    steps: u32,
    /// Backend lookups (20/request) and cache misses per entity (10).
    pub lookups: u32,
}

impl Default for Budget {
    fn default() -> Self {
        Self { steps: 0, lookups: 0 }
    }
}

pub struct Evaluator<'a, H: Host> {
    pub host: &'a mut H,
    pub functions: Vec<&'a FunctionDecl>,
    pub budget: Budget,
    depth: u32,
}

/// Fatal conditions that are NOT absorbable (budget exhaustion).
#[derive(Debug)]
pub struct Fatal(pub String);

type EvalResult = Result<Value, Fatal>;

#[derive(Clone)]
pub struct Scope {
    vars: Vec<(String, Value)>,
}

impl Scope {
    pub fn new() -> Self {
        Self { vars: Vec::new() }
    }
    pub fn bind(&mut self, name: impl Into<String>, value: Value) {
        self.vars.push((name.into(), value));
    }
    pub(crate) fn lookup(&self, name: &str) -> Option<&Value> {
        self.vars.iter().rev().find(|(n, _)| n == name).map(|(_, v)| v)
    }
}

impl Default for Scope {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, H: Host> Evaluator<'a, H> {
    pub fn new(host: &'a mut H, functions: Vec<&'a FunctionDecl>) -> Self {
        Self { host, functions, budget: Budget::default(), depth: 0 }
    }

    fn step(&mut self) -> Result<(), Fatal> {
        self.budget.steps += 1;
        if self.budget.steps > MAX_STEPS {
            return Err(Fatal("evaluation budget exhausted".into()));
        }
        Ok(())
    }

    pub fn eval(&mut self, expr: &Expr, scope: &Scope) -> EvalResult {
        self.step()?;
        Ok(match expr {
            Expr::Null => Value::Null,
            Expr::Bool(b) => Value::Bool(*b),
            Expr::Int(i) => Value::Int(*i),
            Expr::Float(f) => Value::Float(*f),
            Expr::Str(s) => Value::str(s.as_str()),
            Expr::List(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    let v = self.eval(item, scope)?;
                    if v.is_undefined() {
                        return Ok(v);
                    }
                    out.push(v);
                }
                Value::list(out)
            }
            Expr::Map(entries) => {
                let mut out = BTreeMap::new();
                for (k, e) in entries {
                    let v = self.eval(e, scope)?;
                    if v.is_undefined() {
                        return Ok(v);
                    }
                    out.insert(k.clone(), v);
                }
                Value::map(out)
            }
            Expr::Path(parts) => {
                let mut segments = Vec::new();
                for part in parts {
                    match part {
                        PathPart::Static(s) => segments.push(s.clone()),
                        PathPart::Splice(e) => {
                            let v = self.eval(e, scope)?;
                            match v {
                                Value::Str(s) => segments.push(s.to_string()),
                                Value::Path(p) => segments.extend(p.iter().cloned()),
                                other if other.is_undefined() => return Ok(other),
                                other => {
                                    return Ok(Value::undefined(format!(
                                        "path segment must be a string, got {}",
                                        other.type_name()
                                    )));
                                }
                            }
                        }
                    }
                }
                Value::Path(Arc::new(segments))
            }
            Expr::Ident(name) => match scope.lookup(name) {
                Some(v) => v.clone(),
                None => Value::undefined(format!("undefined variable {name}")),
            },
            Expr::Member(target, field) => {
                let base = self.eval(target, scope)?;
                self.member(base, field)
            }
            Expr::Index(target, index) => {
                let base = self.eval(target, scope)?;
                if base.is_undefined() {
                    return Ok(base);
                }
                let idx = self.eval(index, scope)?;
                if idx.is_undefined() {
                    return Ok(idx);
                }
                index_value(&base, &idx)
            }
            Expr::Range(target, lo, hi) => {
                let base = self.eval(target, scope)?;
                if base.is_undefined() {
                    return Ok(base);
                }
                let lo = match lo {
                    Some(e) => match self.eval(e, scope)? {
                        Value::Int(i) => i.max(0) as usize,
                        other if other.is_undefined() => return Ok(other),
                        _ => return Ok(Value::undefined("range bound must be an int")),
                    },
                    None => 0,
                };
                let hi = match hi {
                    Some(e) => match self.eval(e, scope)? {
                        Value::Int(i) => Some(i.max(0) as usize),
                        other if other.is_undefined() => return Ok(other),
                        _ => return Ok(Value::undefined("range bound must be an int")),
                    },
                    None => None,
                };
                range_value(&base, lo, hi)
            }
            Expr::Unary(op, inner) => {
                let v = self.eval(inner, scope)?;
                if v.is_undefined() {
                    return Ok(v);
                }
                match (op, v) {
                    (UnOp::Not, Value::Bool(b)) => Value::Bool(!b),
                    (UnOp::Neg, Value::Int(i)) => match i.checked_neg() {
                        Some(n) => Value::Int(n),
                        None => Value::undefined("integer overflow"),
                    },
                    (UnOp::Neg, Value::Float(f)) => Value::Float(-f),
                    (_, other) => Value::undefined(format!(
                        "operator not supported on {}",
                        other.type_name()
                    )),
                }
            }
            Expr::Binary(BinOp::And, l, r) => self.logical(l, r, scope, false)?,
            Expr::Binary(BinOp::Or, l, r) => self.logical(l, r, scope, true)?,
            Expr::Binary(op, l, r) => {
                let lv = self.eval(l, scope)?;
                if lv.is_undefined() {
                    return Ok(lv);
                }
                let rv = self.eval(r, scope)?;
                if rv.is_undefined() {
                    return Ok(rv);
                }
                binary(*op, &lv, &rv)
            }
            Expr::Ternary(cond, then, otherwise) => {
                let c = self.eval(cond, scope)?;
                match c.as_bool() {
                    Some(true) => self.eval(then, scope)?,
                    Some(false) => self.eval(otherwise, scope)?,
                    None if c.is_undefined() => c,
                    None => Value::undefined("ternary condition must be a bool"),
                }
            }
            Expr::Is(inner, ty) => {
                let v = self.eval(inner, scope)?;
                if v.is_undefined() {
                    return Ok(v);
                }
                Value::Bool(v.matches_type(ty))
            }
            Expr::Call { target, name, args } => self.call(target.as_deref(), name, args, scope)?,
        })
    }

    /// `&&` / `||` with short-circuit *and* error absorption.
    fn logical(&mut self, l: &Expr, r: &Expr, scope: &Scope, is_or: bool) -> EvalResult {
        let lv = self.eval(l, scope)?;
        // Short circuit: true||_ , false&&_ — rhs never evaluated.
        if let Some(b) = lv.as_bool() {
            if b == is_or {
                return Ok(Value::Bool(b));
            }
        }
        let rv = self.eval(r, scope)?;
        Ok(match (lv.as_bool(), rv.as_bool()) {
            (Some(_), Some(b)) => Value::Bool(b),
            // lhs errored: rhs can absorb it (true for ||, false for &&).
            (None, Some(b)) if b == is_or => Value::Bool(b),
            (None, Some(_)) => lv,
            (Some(_), None) => rv,
            (None, None) => lv,
        })
    }

    fn member(&mut self, base: Value, field: &str) -> Value {
        if base.is_undefined() {
            return base;
        }
        match &base {
            // Null member access is an error, not undefined-propagation.
            Value::Null => Value::undefined("null value error"),
            Value::Map(m) => match m.get(field) {
                Some(v) => v.clone(),
                None => Value::undefined(format!("property {field} is undefined")),
            },
            _ => Value::undefined(format!(
                "{} has no property {field}",
                base.type_name()
            )),
        }
    }

    fn call(
        &mut self,
        target: Option<&Expr>,
        name: &str,
        args: &[Expr],
        scope: &Scope,
    ) -> EvalResult {
        // `math.round(x)` and friends are namespaced globals, not methods
        // on a variable — dispatch them before evaluating a "receiver".
        let namespaced = match target {
            Some(Expr::Ident(ns))
                if matches!(ns.as_str(), "math" | "duration" | "latlng" | "timestamp" | "hashing")
                    && scope.lookup(ns).is_none() =>
            {
                Some(format!("{ns}.{name}"))
            }
            _ => None,
        };
        if let Some(global_name) = namespaced {
            let mut argv = Vec::with_capacity(args.len());
            for a in args {
                let v = self.eval(a, scope)?;
                if v.is_undefined() {
                    return Ok(v);
                }
                argv.push(v);
            }
            return self.global_call(&global_name, argv);
        }

        // Evaluate receiver + args first; any undefined aborts the call
        // without invoking it (so get(<undefined>) never hits the backend).
        let receiver = match target {
            Some(t) => {
                let v = self.eval(t, scope)?;
                if v.is_undefined() {
                    return Ok(v);
                }
                Some(v)
            }
            None => None,
        };
        let mut argv = Vec::with_capacity(args.len());
        for a in args {
            let v = self.eval(a, scope)?;
            if v.is_undefined() {
                return Ok(v);
            }
            argv.push(v);
        }

        match receiver {
            Some(recv) => Ok(crate::stdlib::method(&recv, name, &argv)),
            None => {
                // User-defined function?
                if let Some(decl) = self.functions.iter().find(|f| f.name == name).copied() {
                    if decl.params.len() != argv.len() {
                        return Ok(Value::undefined(format!(
                            "function {name} expects {} arguments",
                            decl.params.len()
                        )));
                    }
                    self.depth += 1;
                    if self.depth > MAX_CALL_DEPTH {
                        self.depth -= 1;
                        return Err(Fatal("maximum function call depth exceeded".into()));
                    }
                    let mut inner = Scope::new();
                    // Globals stay visible (request/resource et al).
                    for (n, v) in &scope.vars {
                        if !decl.params.contains(n) {
                            inner.bind(n.clone(), v.clone());
                        }
                    }
                    for (p, v) in decl.params.iter().zip(argv) {
                        inner.bind(p.clone(), v);
                    }
                    for (n, e) in &decl.lets {
                        let v = self.eval(e, &inner)?;
                        inner.bind(n.clone(), v);
                    }
                    let result = self.eval(&decl.body, &inner);
                    self.depth -= 1;
                    return result;
                }
                self.global_call(name, argv)
            }
        }
    }

    fn global_call(&mut self, name: &str, argv: Vec<Value>) -> EvalResult {
        match name {
            "get" | "getAfter" | "exists" | "existsAfter" => {
                let Some(Value::Path(path)) = argv.first().cloned() else {
                    return Ok(Value::undefined(format!("{name}() expects a path")));
                };
                self.budget.lookups += 1;
                if self.budget.lookups > 20 {
                    return Err(Fatal(
                        "Cannot call firestore functions more than 20 times during rules evaluation"
                            .into(),
                    ));
                }
                let after = name.ends_with("After");
                if name.starts_with("get") {
                    match self.host.get_document(&path, after) {
                        Ok(Some(v)) => Ok(v),
                        Ok(None) => Ok(Value::Null),
                        Err(e) => Ok(Value::undefined(e)),
                    }
                } else {
                    match self.host.exists(&path, after) {
                        Ok(b) => Ok(Value::Bool(b)),
                        Err(e) => Ok(Value::undefined(e)),
                    }
                }
            }
            _ => Ok(crate::stdlib::global(name, &argv)),
        }
    }
}

fn binary(op: BinOp, l: &Value, r: &Value) -> Value {
    use BinOp::*;
    match op {
        Eq => Value::Bool(l.equals(r)),
        Ne => Value::Bool(!l.equals(r)),
        Lt | Le | Gt | Ge => match l.compare(r) {
            Some(ord) => Value::Bool(match op {
                Lt => ord.is_lt(),
                Le => ord.is_le(),
                Gt => ord.is_gt(),
                _ => ord.is_ge(),
            }),
            None => Value::undefined(format!(
                "cannot compare {} with {}",
                l.type_name(),
                r.type_name()
            )),
        },
        In => match r {
            Value::List(items) => Value::Bool(items.iter().any(|i| i.equals(l))),
            Value::Map(m) => match l {
                Value::Str(k) => Value::Bool(m.contains_key(k.as_ref())),
                _ => Value::undefined("map membership requires a string key"),
            },
            _ => Value::undefined(format!("'in' not supported on {}", r.type_name())),
        },
        Add | Sub | Mul | Div | Mod => arithmetic(op, l, r),
        And | Or => unreachable!("handled by logical()"),
    }
}

fn arithmetic(op: BinOp, l: &Value, r: &Value) -> Value {
    use BinOp::*;
    // String concat and list/map merge are `+` only.
    if op == Add {
        match (l, r) {
            (Value::Str(a), Value::Str(b)) => return Value::str(format!("{a}{b}")),
            (Value::List(a), Value::List(b)) => {
                let mut out = a.as_ref().clone();
                out.extend(b.iter().cloned());
                return Value::list(out);
            }
            (Value::Timestamp(s, n), Value::Duration(ds, dn))
            | (Value::Duration(ds, dn), Value::Timestamp(s, n)) => {
                return add_timestamp(*s, *n, *ds, *dn);
            }
            _ => {}
        }
    }
    if op == Sub {
        if let (Value::Timestamp(s1, n1), Value::Timestamp(s2, n2)) = (l, r) {
            let total = (*s1 - *s2) * 1_000_000_000 + (*n1 as i64 - *n2 as i64);
            return Value::Duration(total.div_euclid(1_000_000_000), total.rem_euclid(1_000_000_000) as u32);
        }
        if let (Value::Timestamp(s, n), Value::Duration(ds, dn)) = (l, r) {
            return add_timestamp(*s, *n, -*ds, 0).plus_nanos(-(*dn as i64));
        }
    }
    match (l, r) {
        (Value::Int(a), Value::Int(b)) => {
            let result = match op {
                Add => a.checked_add(*b),
                Sub => a.checked_sub(*b),
                Mul => a.checked_mul(*b),
                Div => {
                    if *b == 0 {
                        return Value::undefined("divide by zero");
                    }
                    a.checked_div(*b)
                }
                _ => {
                    if *b == 0 {
                        return Value::undefined("divide by zero");
                    }
                    a.checked_rem(*b)
                }
            };
            match result {
                Some(v) => Value::Int(v),
                None => Value::undefined("integer overflow"),
            }
        }
        (Value::Float(_), _) | (_, Value::Float(_)) => {
            let (a, b) = match (numeric(l), numeric(r)) {
                (Some(a), Some(b)) => (a, b),
                _ => {
                    return Value::undefined(format!(
                        "arithmetic not supported on {} and {}",
                        l.type_name(),
                        r.type_name()
                    ));
                }
            };
            Value::Float(match op {
                Add => a + b,
                Sub => a - b,
                Mul => a * b,
                Div => a / b,
                _ => a % b,
            })
        }
        _ => Value::undefined(format!(
            "arithmetic not supported on {} and {}",
            l.type_name(),
            r.type_name()
        )),
    }
}

impl Value {
    fn plus_nanos(self, nanos: i64) -> Value {
        match self {
            Value::Timestamp(s, n) => {
                let total = s * 1_000_000_000 + n as i64 + nanos;
                Value::Timestamp(
                    total.div_euclid(1_000_000_000),
                    total.rem_euclid(1_000_000_000) as u32,
                )
            }
            other => other,
        }
    }
}

fn add_timestamp(s: i64, n: u32, ds: i64, dn: u32) -> Value {
    let total = (s + ds) * 1_000_000_000 + n as i64 + dn as i64;
    Value::Timestamp(
        total.div_euclid(1_000_000_000),
        total.rem_euclid(1_000_000_000) as u32,
    )
}

fn numeric(v: &Value) -> Option<f64> {
    match v {
        Value::Int(i) => Some(*i as f64),
        Value::Float(f) => Some(*f),
        _ => None,
    }
}

fn index_value(base: &Value, index: &Value) -> Value {
    match (base, index) {
        (Value::List(items), Value::Int(i)) => match usize::try_from(*i)
            .ok()
            .and_then(|i| items.get(i))
        {
            Some(v) => v.clone(),
            None => Value::undefined("index out of bounds"),
        },
        (Value::Str(s), Value::Int(i)) => match usize::try_from(*i)
            .ok()
            .and_then(|i| s.chars().nth(i))
        {
            Some(c) => Value::str(c.to_string()),
            None => Value::undefined("index out of bounds"),
        },
        (Value::Map(m), Value::Str(k)) => match m.get(k.as_ref()) {
            Some(v) => v.clone(),
            None => Value::undefined(format!("property {k} is undefined")),
        },
        (Value::Path(p), Value::Int(i)) => match usize::try_from(*i).ok().and_then(|i| p.get(i)) {
            Some(s) => Value::str(s.as_str()),
            None => Value::undefined("index out of bounds"),
        },
        _ => Value::undefined(format!(
            "cannot index {} with {}",
            base.type_name(),
            index.type_name()
        )),
    }
}

fn range_value(base: &Value, lo: usize, hi: Option<usize>) -> Value {
    match base {
        Value::List(items) => {
            let hi = hi.unwrap_or(items.len()).min(items.len());
            if lo > hi {
                return Value::undefined("illegal range");
            }
            Value::list(items[lo..hi].to_vec())
        }
        Value::Str(s) => {
            let chars: Vec<char> = s.chars().collect();
            let hi = hi.unwrap_or(chars.len()).min(chars.len());
            if lo > hi {
                return Value::undefined("illegal range");
            }
            Value::str(chars[lo..hi].iter().collect::<String>())
        }
        Value::Path(p) => {
            let hi = hi.unwrap_or(p.len()).min(p.len());
            if lo > hi {
                return Value::undefined("illegal range");
            }
            Value::Path(Arc::new(p[lo..hi].to_vec()))
        }
        _ => Value::undefined(format!("cannot slice {}", base.type_name())),
    }
}
