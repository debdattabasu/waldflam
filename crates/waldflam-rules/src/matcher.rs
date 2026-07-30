//! Path matching and rule evaluation: walks `match` blocks binding captures,
//! then evaluates the `allow` statements for the requested operation.
//!
//! Semantics (docs §7): `read` expands to get/list, `write` to
//! create/update/delete (one level, rule-side names case-insensitive);
//! sibling allow statements combine as ternary-OR — any `true` rescues an
//! erroring sibling, and errors only deny if nothing granted.

use std::collections::BTreeMap;

use crate::ast::*;
use crate::eval::{Evaluator, Fatal, Host, Scope};
use crate::value::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Get,
    List,
    Create,
    Update,
    Delete,
}

impl Operation {
    pub fn id(&self) -> &'static str {
        match self {
            Operation::Get => "get",
            Operation::List => "list",
            Operation::Create => "create",
            Operation::Update => "update",
            Operation::Delete => "delete",
        }
    }

    /// Does a rule-side operation name cover this operation?
    fn covered_by(&self, rule_method: &str) -> bool {
        let m = rule_method.to_ascii_lowercase();
        m == self.id()
            || match self {
                Operation::Get | Operation::List => m == "read",
                _ => m == "write",
            }
    }
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
}

/// Evaluates a request against the ruleset.
///
/// `path` is the resource path *below* the service root, e.g.
/// `["databases", "(default)", "documents", "users", "alice"]`.
pub fn evaluate<'a, H: Host>(
    ruleset: &'a Ruleset,
    service_name: &str,
    operation: Operation,
    path: &[String],
    globals: &[(String, Value)],
    host: &mut H,
) -> Result<Decision, Fatal> {
    let Some(service) = ruleset.services.iter().find(|s| s.name == service_name) else {
        return Ok(Decision::Deny);
    };

    let mut granted = false;
    let mut errored = false;
    for rule in &service.matches {
        let mut functions: Vec<&FunctionDecl> = service.functions.iter().collect();
        walk(
            ruleset.version,
            rule,
            path,
            0,
            &mut Vec::new(),
            &mut functions,
            operation,
            globals,
            host,
            &mut granted,
            &mut errored,
        )?;
        if granted {
            return Ok(Decision::Allow);
        }
    }
    let _ = errored; // errors deny, same as no match
    Ok(Decision::Deny)
}

#[allow(clippy::too_many_arguments)]
fn walk<'a, H: Host>(
    version: Version,
    rule: &'a MatchRule,
    path: &[String],
    consumed: usize,
    captures: &mut Vec<(String, Value)>,
    functions: &mut Vec<&'a FunctionDecl>,
    operation: Operation,
    globals: &[(String, Value)],
    host: &mut H,
    granted: &mut bool,
    errored: &mut bool,
) -> Result<(), Fatal> {
    let captures_before = captures.len();
    let functions_before = functions.len();

    let Some(after) = match_segments(version, &rule.path, path, consumed, captures) else {
        captures.truncate(captures_before);
        return Ok(());
    };
    for f in &rule.functions {
        functions.push(f);
    }

    // Fully consumed: this rule's allow statements apply.
    if after == path.len() {
        let mut scope = Scope::new();
        for (name, value) in globals {
            scope.bind(name.clone(), value.clone());
        }
        for (name, value) in captures.iter() {
            scope.bind(name.clone(), value.clone());
        }
        for allow in &rule.allows {
            if !allow.methods.iter().any(|m| operation.covered_by(m)) {
                continue;
            }
            let mut ev = Evaluator::new(host, functions.clone());
            match ev.eval(&allow.condition, &scope)? {
                Value::Bool(true) => {
                    *granted = true;
                    captures.truncate(captures_before);
                    functions.truncate(functions_before);
                    return Ok(());
                }
                Value::Bool(false) => {}
                _ => *errored = true,
            }
        }
    }

    for child in &rule.children {
        walk(
            version, child, path, after, captures, functions, operation, globals, host, granted,
            errored,
        )?;
        if *granted {
            break;
        }
    }
    captures.truncate(captures_before);
    functions.truncate(functions_before);
    Ok(())
}

/// Matches this rule's path segments against `path[consumed..]`, binding
/// captures. Returns the new consumed index, or None if it doesn't match.
fn match_segments(
    version: Version,
    segments: &[MatchSeg],
    path: &[String],
    consumed: usize,
    captures: &mut Vec<(String, Value)>,
) -> Option<usize> {
    let mut i = consumed;
    for (si, seg) in segments.iter().enumerate() {
        match seg {
            MatchSeg::Literal(lit) => {
                if path.get(i)? != lit {
                    return None;
                }
                i += 1;
            }
            MatchSeg::Capture(name) => {
                let value = path.get(i)?;
                captures.push((name.clone(), Value::str(value.as_str())));
                i += 1;
            }
            MatchSeg::Glob(name) => {
                // v1: must be terminal and matches >= 1 segment.
                // v2: matches >= 0 segments, and trailing segments must still
                // line up (we take the longest split that leaves room).
                let remaining_after = segments.len() - si - 1;
                if path.len() < i + remaining_after {
                    return None;
                }
                let take = path.len() - remaining_after - i;
                if version == Version::V1 && take == 0 {
                    return None;
                }
                let captured: Vec<String> = path[i..i + take].to_vec();
                captures.push((
                    name.clone(),
                    Value::Path(std::sync::Arc::new(captured)),
                ));
                i += take;
            }
        }
    }
    Some(i)
}

/// Builds the `request` map for an operation.
pub struct RequestBuilder {
    pub auth: Option<Value>,
    pub time: Value,
    pub path: Vec<String>,
    pub method: Operation,
    pub resource: Option<Value>,
}

impl RequestBuilder {
    pub fn build(self) -> Value {
        let mut map = BTreeMap::new();
        map.insert("auth".into(), self.auth.unwrap_or(Value::Null));
        map.insert("time".into(), self.time);
        map.insert("method".into(), Value::str(self.method.id()));
        map.insert(
            "path".into(),
            Value::Path(std::sync::Arc::new(self.path)),
        );
        if let Some(resource) = self.resource {
            map.insert("resource".into(), resource);
        }
        Value::map(map)
    }
}
