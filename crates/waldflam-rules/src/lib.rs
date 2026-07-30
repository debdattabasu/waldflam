//! Firebase Security Rules engine: lexer, parser (CEL precedence), and a
//! tree-walking evaluator with error-containment-as-deny semantics.
//!
//! Written from scratch against the behavioral spec in
//! docs/architecture.md §7 — no CEL dependency.
