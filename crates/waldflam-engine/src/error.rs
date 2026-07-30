#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("document not found: {0}")]
    NotFound(String),
    #[error("document already exists: {0}")]
    AlreadyExists(String),
    #[error("transaction aborted")]
    Aborted,
    #[error("failed precondition: {0}")]
    FailedPrecondition(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("not implemented: {0}")]
    Unimplemented(&'static str),
    #[error(transparent)]
    Mongo(#[from] mongodb::error::Error),
}
