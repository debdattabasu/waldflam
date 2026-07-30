//! Storage and query engine: Firestore semantics on MongoDB.
//!
//! Documents live in one flat collection per Firestore database:
//! `_id` = full document path, `$indexedFields` = order-preserving encoded
//! values for implicitly indexed fields, `$payloadFields` = the rest.
//! See docs/architecture.md §6.

pub mod commit;
pub mod encoding;
pub mod error;
pub mod fields;
pub mod index_key;
pub mod order;
pub mod path;
pub mod query;
pub mod store;
pub mod txn;

pub use error::EngineError;
