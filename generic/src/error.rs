use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("sensor error: {0}")]
    Sensor(String),

    #[error("pipeline error: {0}")]
    Pipeline(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("platform error: {0}")]
    Platform(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, AgentError>;
