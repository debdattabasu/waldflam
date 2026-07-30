//! Firestore resource names.
//!
//! Wire format: `projects/{project}/databases/{database}/documents/{path…}`
//! where `{path…}` alternates collection and document segments. An odd number
//! of relative segments names a collection, an even number a document.

use std::fmt;

use crate::EngineError;

pub const DEFAULT_DATABASE_ID: &str = "(default)";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DatabaseName {
    pub project_id: String,
    pub database_id: String,
}

impl DatabaseName {
    pub fn new(project_id: impl Into<String>, database_id: impl Into<String>) -> Self {
        Self {
            project_id: project_id.into(),
            database_id: database_id.into(),
        }
    }

    /// Parses `projects/{p}/databases/{d}`, tolerating a trailing
    /// `/documents[/…]` remainder (returned separately).
    pub fn parse_prefix(name: &str) -> Result<(Self, &str), EngineError> {
        let bad = || EngineError::InvalidArgument(format!("invalid database name: {name:?}"));
        let rest = name.strip_prefix("projects/").ok_or_else(bad)?;
        let (project_id, rest) = rest.split_once('/').ok_or_else(bad)?;
        let rest = rest.strip_prefix("databases/").ok_or_else(bad)?;
        let (database_id, remainder) = match rest.split_once('/') {
            Some((db, tail)) => (db, tail),
            None => (rest, ""),
        };
        if project_id.is_empty() || database_id.is_empty() {
            return Err(bad());
        }
        Ok((Self::new(project_id, database_id), remainder))
    }

    pub fn parse(name: &str) -> Result<Self, EngineError> {
        match Self::parse_prefix(name)? {
            (db, "") => Ok(db),
            _ => Err(EngineError::InvalidArgument(format!(
                "invalid database name: {name:?}"
            ))),
        }
    }

    /// `projects/{p}/databases/{d}/documents` — the parent of all root
    /// collections and the `parent` sent by clients for root-level queries.
    pub fn documents_root(&self) -> String {
        format!("{self}/documents")
    }
}

impl fmt::Display for DatabaseName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "projects/{}/databases/{}", self.project_id, self.database_id)
    }
}

/// A path relative to `{database}/documents`: alternating
/// collection/document segments. Empty = the documents root itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResourcePath {
    segments: Vec<String>,
}

impl ResourcePath {
    pub fn root() -> Self {
        Self { segments: Vec::new() }
    }

    pub fn from_segments(segments: Vec<String>) -> Result<Self, EngineError> {
        for seg in &segments {
            validate_segment(seg)?;
        }
        Ok(Self { segments })
    }

    /// Parses a `/`-separated relative path (no leading or trailing slash).
    pub fn parse(path: &str) -> Result<Self, EngineError> {
        if path.is_empty() {
            return Ok(Self::root());
        }
        Self::from_segments(path.split('/').map(str::to_owned).collect())
    }

    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn is_document(&self) -> bool {
        !self.segments.is_empty() && self.segments.len() % 2 == 0
    }

    pub fn is_collection(&self) -> bool {
        self.segments.len() % 2 == 1
    }

    /// Final segment: the document id (documents) or collection id
    /// (collections). None for the root.
    pub fn last_id(&self) -> Option<&str> {
        self.segments.last().map(String::as_str)
    }

    /// For a document path, the id of the collection containing it.
    pub fn collection_id(&self) -> Option<&str> {
        if self.is_document() {
            self.segments.get(self.segments.len() - 2).map(String::as_str)
        } else {
            self.last_id()
        }
    }

    pub fn parent(&self) -> Option<Self> {
        if self.segments.is_empty() {
            return None;
        }
        Some(Self {
            segments: self.segments[..self.segments.len() - 1].to_vec(),
        })
    }

    pub fn child(&self, id: &str) -> Result<Self, EngineError> {
        validate_segment(id)?;
        let mut segments = self.segments.clone();
        segments.push(id.to_owned());
        Ok(Self { segments })
    }
}

impl fmt::Display for ResourcePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.segments.join("/"))
    }
}

/// A fully-qualified document or collection name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceName {
    pub database: DatabaseName,
    pub path: ResourcePath,
}

impl ResourceName {
    /// Parses `projects/{p}/databases/{d}/documents[/{path…}]`.
    pub fn parse(name: &str) -> Result<Self, EngineError> {
        let (database, remainder) = DatabaseName::parse_prefix(name)?;
        let path = match remainder {
            "" => {
                return Err(EngineError::InvalidArgument(format!(
                    "resource name missing /documents: {name:?}"
                )));
            }
            "documents" => ResourcePath::root(),
            _ => {
                let rel = remainder.strip_prefix("documents/").ok_or_else(|| {
                    EngineError::InvalidArgument(format!("invalid resource name: {name:?}"))
                })?;
                ResourcePath::parse(rel)?
            }
        };
        Ok(Self { database, path })
    }

    pub fn parse_document(name: &str) -> Result<Self, EngineError> {
        let parsed = Self::parse(name)?;
        if !parsed.path.is_document() {
            return Err(EngineError::InvalidArgument(format!(
                "not a document name: {name:?}"
            )));
        }
        Ok(parsed)
    }
}

impl fmt::Display for ResourceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}/documents", self.database)
        } else {
            write!(f, "{}/documents/{}", self.database, self.path)
        }
    }
}

fn validate_segment(seg: &str) -> Result<(), EngineError> {
    if seg.is_empty() {
        return Err(EngineError::InvalidArgument("empty path segment".into()));
    }
    Ok(())
}

/// Ids matching `__.*__` are reserved; writes must reject them.
pub fn is_reserved_id(id: &str) -> bool {
    id.len() >= 4 && id.starts_with("__") && id.ends_with("__")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_database_names() {
        let db = DatabaseName::parse("projects/p1/databases/(default)").unwrap();
        assert_eq!(db.project_id, "p1");
        assert_eq!(db.database_id, "(default)");
        assert_eq!(db.to_string(), "projects/p1/databases/(default)");
        assert!(DatabaseName::parse("projects/p1").is_err());
        assert!(DatabaseName::parse("projects//databases/d").is_err());
        assert!(DatabaseName::parse("projects/p/databases/d/documents").is_err());
    }

    #[test]
    fn parses_resource_names() {
        let n = ResourceName::parse("projects/p/databases/(default)/documents/users/alice").unwrap();
        assert!(n.path.is_document());
        assert_eq!(n.path.collection_id(), Some("users"));
        assert_eq!(n.path.last_id(), Some("alice"));
        assert_eq!(
            n.to_string(),
            "projects/p/databases/(default)/documents/users/alice"
        );

        let c = ResourceName::parse("projects/p/databases/d/documents/users").unwrap();
        assert!(c.path.is_collection());

        let root = ResourceName::parse("projects/p/databases/d/documents").unwrap();
        assert!(root.path.is_empty());
        assert_eq!(root.to_string(), "projects/p/databases/d/documents");

        assert!(ResourceName::parse("projects/p/databases/d").is_err());
        assert!(ResourceName::parse("projects/p/databases/d/documents/users//x").is_err());
        assert!(
            ResourceName::parse_document("projects/p/databases/d/documents/users").is_err()
        );
    }

    #[test]
    fn navigates_paths() {
        let doc = ResourcePath::parse("users/alice/posts/p1").unwrap();
        assert!(doc.is_document());
        assert_eq!(doc.collection_id(), Some("posts"));
        let coll = doc.parent().unwrap();
        assert!(coll.is_collection());
        assert_eq!(coll.to_string(), "users/alice/posts");
        assert_eq!(
            coll.parent().unwrap().parent().unwrap().parent().unwrap(),
            ResourcePath::root()
        );
    }

    #[test]
    fn reserved_ids() {
        assert!(is_reserved_id("__id__"));
        assert!(is_reserved_id("____"));
        assert!(!is_reserved_id("__x"));
        assert!(!is_reserved_id("x__"));
        assert!(!is_reserved_id("___"));
        assert!(!is_reserved_id("normal"));
    }
}
