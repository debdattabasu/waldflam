//! Firebase Security Rules engine: lexer, parser (CEL-aligned precedence),
//! and a tree-walking evaluator with error-containment-as-deny semantics.
//!
//! Written from scratch against the behavioral spec in
//! docs/architecture.md §7 — no CEL dependency, so upstream churn can't
//! change our semantics.

pub mod ast;
pub mod eval;
pub mod lexer;
pub mod matcher;
pub mod parser;
pub mod stdlib;
pub mod value;

pub use ast::{Ruleset, Version};
pub use eval::{Evaluator, Host, Scope};
pub use matcher::{Decision, Operation, evaluate};
pub use parser::{Issue, parse};
pub use value::Value;

#[cfg(test)]
mod tests;
