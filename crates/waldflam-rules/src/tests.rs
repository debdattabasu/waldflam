//! Spec tests. Each case encodes a behavior specified in
//! docs/architecture.md §7 — these are the semantics that make a rules
//! engine correct rather than merely plausible.

use std::collections::BTreeMap;

use crate::ast::Version;
use crate::eval::{Evaluator, Host, Scope};
use crate::matcher::{Decision, Operation, evaluate};
use crate::parser::{parse, parse_expression};
use crate::value::Value;

/// Host with a fixed document set.
struct TestHost {
    docs: BTreeMap<String, Value>,
    calls: u32,
}

impl TestHost {
    fn new() -> Self {
        Self { docs: BTreeMap::new(), calls: 0 }
    }
    fn with(mut self, path: &str, fields: Vec<(&str, Value)>) -> Self {
        let mut data = BTreeMap::new();
        let mut inner = BTreeMap::new();
        for (k, v) in fields {
            inner.insert(k.to_owned(), v);
        }
        data.insert("data".to_owned(), Value::map(inner));
        self.docs.insert(path.to_owned(), Value::map(data));
        self
    }
}

impl Host for TestHost {
    fn get_document(&mut self, path: &[String], _after: bool) -> Result<Option<Value>, String> {
        self.calls += 1;
        Ok(self.docs.get(&path.join("/")).cloned())
    }
    fn exists(&mut self, path: &[String], _after: bool) -> Result<bool, String> {
        self.calls += 1;
        Ok(self.docs.contains_key(&path.join("/")))
    }
}

fn eval_expr(source: &str, bindings: Vec<(&str, Value)>) -> Value {
    let expr = parse_expression(source).expect("parse");
    let mut host = TestHost::new();
    let mut ev = Evaluator::new(&mut host, Vec::new());
    let mut scope = Scope::new();
    for (name, value) in bindings {
        scope.bind(name, value);
    }
    ev.eval(&expr, &scope).expect("no fatal")
}

fn truth(source: &str) -> Option<bool> {
    eval_expr(source, Vec::new()).as_bool()
}

#[test]
fn logical_absorption_table() {
    // The canonical table from docs §7. `undefinedVar` is an error value.
    assert_eq!(truth("true || undefinedVar"), Some(true), "short circuit ||");
    assert_eq!(truth("false && undefinedVar"), Some(false), "short circuit &&");
    assert_eq!(truth("undefinedVar || true"), Some(true), "|| absorbs error");
    assert_eq!(truth("undefinedVar && false"), Some(false), "&& absorbs error");
    assert_eq!(truth("undefinedVar || false"), None, "error survives");
    assert_eq!(truth("undefinedVar && true"), None, "error survives");
    assert_eq!(truth("false || undefinedVar"), None, "error survives");
    assert_eq!(truth("true && undefinedVar"), None, "error survives");
    assert_eq!(truth("undefinedVar || undefinedVar"), None, "both error");
}

#[test]
fn canonical_auth_idiom_denies_when_unauthenticated() {
    // The single most common rules idiom: it must DENY, not blow up, when
    // request.auth is null (the 2019 reference implementation got this wrong).
    let mut request = BTreeMap::new();
    request.insert("auth".to_owned(), Value::Null);
    let v = eval_expr(
        "request.auth != null && request.auth.uid == 'alice'",
        vec![("request", Value::map(request))],
    );
    assert_eq!(v.as_bool(), Some(false));
}

#[test]
fn null_member_access_is_an_error() {
    let mut request = BTreeMap::new();
    request.insert("auth".to_owned(), Value::Null);
    let v = eval_expr("request.auth.uid", vec![("request", Value::map(request))]);
    assert!(v.is_undefined());
}

#[test]
fn type_semantics() {
    // int/float distinction with numeric equality across them.
    assert_eq!(truth("1 == 1.0"), Some(true));
    assert_eq!(truth("1 is int"), Some(true));
    assert_eq!(truth("1.0 is float"), Some(true));
    assert_eq!(truth("1 is float"), Some(false));
    assert_eq!(truth("1 is number"), Some(true));
    assert_eq!(truth("1.0 is number"), Some(true));
    // Cross-type equality is false, not an error.
    assert_eq!(truth("1 == 'x'"), Some(false));
    assert_eq!(truth("null == 'x'"), Some(false));
    // Cross-type ordering IS an error.
    assert_eq!(truth("1 < 'x'"), None);
    // Integer overflow errors rather than wrapping.
    assert!(eval_expr("9223372036854775807 + 1", Vec::new()).is_undefined());
    assert!(eval_expr("1 / 0", Vec::new()).is_undefined());
    assert_eq!(truth("7 / 2 == 3"), Some(true), "int division truncates");
    assert_eq!(truth("'a' + 'b' == 'ab'"), Some(true));
}

#[test]
fn precedence_matches_cel() {
    // The 2019 implementation had these inverted — hence explicit tests.
    assert_eq!(truth("1 + 2 == 3"), Some(true));
    assert_eq!(truth("2 + 4 * 3 == 14"), Some(true));
    assert_eq!(truth("!true == false"), Some(true));
    assert_eq!(truth("!(true && false)"), Some(true));
    assert_eq!(truth("true || false && false"), Some(true), "&& binds tighter");
    assert_eq!(truth("1 < 2 == true"), Some(true), "comparison over equality");
    // `==` binds tighter than `?:`, so this is `true ? 1 : (2 == 1)` → int 1.
    assert_eq!(eval_expr("true ? 1 : 2 == 1", Vec::new()).type_name(), "int");
    assert_eq!(truth("(true ? 1 : 2) == 1"), Some(true));
}

#[test]
fn stdlib_behaviors() {
    // matches() is a FULL match.
    assert_eq!(truth("'abc'.matches('b')"), Some(false));
    assert_eq!(truth("'abc'.matches('a.c')"), Some(true));
    assert_eq!(truth("'a@b.com'.matches('.*@.*[.].*')"), Some(true));
    assert_eq!(truth("'ABC'.lower() == 'abc'"), Some(true));
    assert_eq!(truth("'  x '.trim() == 'x'"), Some(true));
    assert_eq!(truth("'abc'.size() == 3"), Some(true));
    assert_eq!(truth("['a','b'].hasAll(['a'])"), Some(true));
    assert_eq!(truth("['a'].hasOnly(['a','b'])"), Some(true));
    assert_eq!(truth("['a','b'].hasOnly(['a'])"), Some(false));
    assert_eq!(truth("['a','b'].hasAny(['b','z'])"), Some(true));
    assert_eq!(truth("['a','b'].join(',') == 'a,b'"), Some(true));
    assert_eq!(truth("{'a': 1}.keys() == ['a']"), Some(true));
    assert_eq!(truth("'a' in {'a': 1}"), Some(true));
    assert_eq!(truth("2 in [1,2,3]"), Some(true));
    assert_eq!(truth("[1,2,3][1] == 2"), Some(true));
    assert_eq!(truth("'abcd'[1:3] == 'bc'"), Some(true));
    // math: round returns int, floor/ceil return float.
    assert_eq!(truth("math.round(1.6) == 2"), Some(true));
    assert_eq!(truth("math.floor(1.6) is float"), Some(true));
    assert_eq!(truth("math.abs(-3) == 3"), Some(true));
    // duration/timestamp constructors.
    assert_eq!(truth("duration.value(1, 'h').seconds() == 3600"), Some(true));
    assert_eq!(truth("timestamp.date(2026, 7, 30).year() == 2026"), Some(true));
    assert_eq!(truth("timestamp.date(2026, 7, 30).month() == 7"), Some(true));
    assert_eq!(truth("timestamp.date(2026, 7, 30).day() == 30"), Some(true));
    // map.diff
    assert_eq!(truth("{'a':1,'b':2}.diff({'a':1,'b':3}).changedKeys() == ['b']"), Some(true));
}

fn decide(rules: &str, op: Operation, path: &[&str], globals: Vec<(&str, Value)>) -> Decision {
    decide_with_host(rules, op, path, globals, TestHost::new())
}

fn decide_with_host(
    rules: &str,
    op: Operation,
    path: &[&str],
    globals: Vec<(&str, Value)>,
    mut host: TestHost,
) -> Decision {
    let ruleset = parse(rules).expect("parse rules");
    let path: Vec<String> = path.iter().map(|s| (*s).to_owned()).collect();
    let globals: Vec<(String, Value)> =
        globals.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
    evaluate(&ruleset, "cloud.firestore", op, &path, &globals, &mut host).expect("no fatal")
}

const OPEN: &str = r#"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
"#;

#[test]
fn open_rules_allow_everything() {
    for op in
        [Operation::Get, Operation::List, Operation::Create, Operation::Update, Operation::Delete]
    {
        assert_eq!(
            decide(
                OPEN,
                op,
                &["databases", "(default)", "documents", "users", "alice"],
                Vec::new()
            ),
            Decision::Allow,
            "{op:?}"
        );
    }
}

#[test]
fn closed_rules_deny_everything() {
    let rules = r#"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false;
    }
  }
}"#;
    assert_eq!(
        decide(
            rules,
            Operation::Get,
            &["databases", "(default)", "documents", "c", "d"],
            Vec::new()
        ),
        Decision::Deny
    );
}

#[test]
fn read_write_expansion_and_captures() {
    let rules = r#"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read: if userId == 'alice';
      allow create: if userId == 'bob';
    }
  }
}"#;
    let alice = ["databases", "(default)", "documents", "users", "alice"];
    let bob = ["databases", "(default)", "documents", "users", "bob"];
    // `read` covers get and list.
    assert_eq!(decide(rules, Operation::Get, &alice, Vec::new()), Decision::Allow);
    assert_eq!(decide(rules, Operation::List, &alice, Vec::new()), Decision::Allow);
    // but not create.
    assert_eq!(decide(rules, Operation::Create, &alice, Vec::new()), Decision::Deny);
    assert_eq!(decide(rules, Operation::Create, &bob, Vec::new()), Decision::Allow);
    assert_eq!(decide(rules, Operation::Get, &bob, Vec::new()), Decision::Deny);
}

#[test]
fn ownership_rule_with_auth() {
    let rules = r#"
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {
    match /users/{uid} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
  }
}"#;
    let path = ["databases", "(default)", "documents", "users", "alice"];

    let mut auth = BTreeMap::new();
    auth.insert("uid".to_owned(), Value::str("alice"));
    let mut request = BTreeMap::new();
    request.insert("auth".to_owned(), Value::map(auth));
    assert_eq!(
        decide(rules, Operation::Update, &path, vec![("request", Value::map(request))]),
        Decision::Allow
    );

    // Wrong user.
    let mut auth = BTreeMap::new();
    auth.insert("uid".to_owned(), Value::str("bob"));
    let mut request = BTreeMap::new();
    request.insert("auth".to_owned(), Value::map(auth));
    assert_eq!(
        decide(rules, Operation::Update, &path, vec![("request", Value::map(request))]),
        Decision::Deny
    );

    // Unauthenticated — must deny, not error out.
    let mut request = BTreeMap::new();
    request.insert("auth".to_owned(), Value::Null);
    assert_eq!(
        decide(rules, Operation::Get, &path, vec![("request", Value::map(request))]),
        Decision::Deny
    );
}

#[test]
fn sibling_allow_rescues_erroring_sibling() {
    // First allow errors; the second grants → overall Allow (ternary-OR).
    let rules = r#"
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {
    match /c/{id} {
      allow get: if undefinedVar.field == 1;
      allow get: if true;
    }
  }
}"#;
    assert_eq!(
        decide(
            rules,
            Operation::Get,
            &["databases", "(default)", "documents", "c", "x"],
            Vec::new()
        ),
        Decision::Allow
    );
}

#[test]
fn v2_glob_matches_zero_segments_v1_requires_one() {
    let body = |version: &str| {
        format!(
            r#"
rules_version = '{version}';
service cloud.firestore {{
  match /databases/{{db}}/documents {{
    match /c/{{rest=**}} {{
      allow read: if true;
    }}
  }}
}}"#
        )
    };
    let deep = ["databases", "(default)", "documents", "c", "d", "sub", "x"];
    let bare = ["databases", "(default)", "documents", "c"];
    // Deep paths match under both versions.
    assert_eq!(decide(&body("2"), Operation::Get, &deep, Vec::new()), Decision::Allow);
    assert_eq!(decide(&body("1"), Operation::Get, &deep, Vec::new()), Decision::Allow);
    // Zero-segment: v2 matches, v1 does not.
    assert_eq!(decide(&body("2"), Operation::Get, &bare, Vec::new()), Decision::Allow);
    assert_eq!(decide(&body("1"), Operation::Get, &bare, Vec::new()), Decision::Deny);
}

#[test]
fn user_functions_and_nested_matches() {
    let rules = r#"
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {
    function isSignedIn() {
      return request.auth != null;
    }
    function isOwner(uid) {
      let signed = isSignedIn();
      return signed && request.auth.uid == uid;
    }
    match /users/{uid} {
      allow read: if isSignedIn();
      match /private/{doc} {
        allow read: if isOwner(uid);
      }
    }
  }
}"#;
    let mut auth = BTreeMap::new();
    auth.insert("uid".to_owned(), Value::str("alice"));
    let mut request = BTreeMap::new();
    request.insert("auth".to_owned(), Value::map(auth));
    let globals = vec![("request", Value::map(request))];

    assert_eq!(
        decide(
            rules,
            Operation::Get,
            &["databases", "(default)", "documents", "users", "alice"],
            globals.clone()
        ),
        Decision::Allow
    );
    assert_eq!(
        decide(
            rules,
            Operation::Get,
            &["databases", "(default)", "documents", "users", "alice", "private", "p1"],
            globals.clone()
        ),
        Decision::Allow,
        "nested match with capture from parent"
    );
    assert_eq!(
        decide(
            rules,
            Operation::Get,
            &["databases", "(default)", "documents", "users", "bob", "private", "p1"],
            globals
        ),
        Decision::Deny,
        "not the owner"
    );
}

#[test]
fn get_and_exists_against_the_host() {
    let rules = r#"
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {
    match /posts/{post} {
      allow update: if get(/databases/$(db)/documents/roles/$(request.auth.uid)).data.admin == true;
      allow delete: if exists(/databases/$(db)/documents/roles/$(request.auth.uid));
    }
  }
}"#;
    let host = TestHost::new()
        .with("databases/(default)/documents/roles/alice", vec![("admin", Value::Bool(true))]);
    let mut auth = BTreeMap::new();
    auth.insert("uid".to_owned(), Value::str("alice"));
    let mut request = BTreeMap::new();
    request.insert("auth".to_owned(), Value::map(auth));
    let globals = vec![("request", Value::map(request))];
    let path = ["databases", "(default)", "documents", "posts", "p1"];

    assert_eq!(
        decide_with_host(rules, Operation::Update, &path, globals.clone(), host),
        Decision::Allow
    );
    assert_eq!(
        decide_with_host(rules, Operation::Delete, &path, globals.clone(), TestHost::new()),
        Decision::Deny,
        "missing role document"
    );

    // Non-admin role: get() succeeds but the value denies.
    let host = TestHost::new()
        .with("databases/(default)/documents/roles/alice", vec![("admin", Value::Bool(false))]);
    assert_eq!(decide_with_host(rules, Operation::Update, &path, globals, host), Decision::Deny);
}

#[test]
fn rejects_malformed_rules() {
    assert!(parse("service cloud.firestore {").is_err());
    assert!(parse("rules_version = '3'; service cloud.firestore {}").is_err());
    // v1 glob must be terminal.
    assert!(parse(
        "rules_version = '1';\nservice cloud.firestore {\n match /a/{x=**}/b { allow read: if true; }\n}"
    )
    .is_err());
    // Two globs in one path.
    assert!(parse(
        "rules_version = '2';\nservice cloud.firestore {\n match /a/{x=**}/b/{y=**} { allow read: if true; }\n}"
    )
    .is_err());
    // Unknown operation name.
    assert!(parse(
        "rules_version = '2';\nservice cloud.firestore {\n match /a/{b} { allow frobnicate: if true; }\n}"
    )
    .is_err());
}

#[test]
fn comments_and_allow_without_condition() {
    // Leading comments broke the 2019 implementation; block comments too.
    let rules = r#"
// Top-level comment.
rules_version = '2';
/* block
   comment */
service cloud.firestore {
  match /databases/{db}/documents {
    match /public/{doc} {
      // bare allow means "if true"
      allow read;
    }
  }
}"#;
    assert_eq!(
        decide(
            rules,
            Operation::Get,
            &["databases", "(default)", "documents", "public", "x"],
            Vec::new()
        ),
        Decision::Allow
    );
}

#[test]
fn recursion_is_bounded_not_hung() {
    // Direct recursion is banned upstream at compile time; we bound it at
    // evaluation so a malicious ruleset can't hang the server.
    let rules = r#"
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {
    function loop(n) {
      return loop(n + 1);
    }
    match /c/{id} {
      allow read: if loop(0);
    }
  }
}"#;
    let ruleset = parse(rules).expect("parse");
    let mut host = TestHost::new();
    let path: Vec<String> =
        ["databases", "(default)", "documents", "c", "x"].iter().map(|s| (*s).to_owned()).collect();
    let result = evaluate(&ruleset, "cloud.firestore", Operation::Get, &path, &[], &mut host);
    assert!(result.is_err(), "runaway recursion must be fatal, not a hang");
}

#[test]
fn lookup_budget_is_enforced() {
    let rules = r#"
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {
    match /c/{id} {
      allow read: if exists(/databases/$(db)/documents/x/a) &&
                     exists(/databases/$(db)/documents/x/b) &&
                     exists(/databases/$(db)/documents/x/c);
    }
  }
}"#;
    // All three exist → allowed, and exactly 3 lookups happened.
    let host = TestHost::new()
        .with("databases/(default)/documents/x/a", vec![])
        .with("databases/(default)/documents/x/b", vec![])
        .with("databases/(default)/documents/x/c", vec![]);
    assert_eq!(
        decide_with_host(
            rules,
            Operation::Get,
            &["databases", "(default)", "documents", "c", "x"],
            Vec::new(),
            host
        ),
        Decision::Allow
    );
}

#[test]
fn undefined_argument_short_circuits_before_backend_call() {
    // get(<undefined path>) must not hit the host at all.
    let expr = parse_expression("get(/a/$(missingVar)/b)").expect("parse");
    let mut host = TestHost::new();
    let mut ev = Evaluator::new(&mut host, Vec::new());
    let v = ev.eval(&expr, &Scope::new()).expect("no fatal");
    assert!(v.is_undefined());
    assert_eq!(host.calls, 0, "backend must not be called");
}

#[test]
fn version_defaults_to_v1_when_absent() {
    let ruleset =
        parse("service cloud.firestore { match /a/{b} { allow read: if true; } }").expect("parse");
    assert_eq!(ruleset.version, Version::V1);
}
