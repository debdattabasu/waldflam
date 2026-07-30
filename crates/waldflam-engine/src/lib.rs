//! Storage and query engine: Firestore semantics on MongoDB.
//!
//! Documents live in one flat collection per Firestore database:
//! `_id` = full document path, `$indexedFields` = order-preserving encoded
//! values for implicitly indexed fields, `$payloadFields` = the rest.
//! See docs/architecture.md §6.

pub mod encoding;
pub mod error;
pub mod index_key;
pub mod order;
pub mod path;
pub mod store;

pub use error::EngineError;
