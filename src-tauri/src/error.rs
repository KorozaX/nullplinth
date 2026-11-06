use serde::Serialize;

/// Error type returned by every Tauri command. Serialised as a plain string so the
/// frontend can render it without special-casing error shapes.
#[derive(Debug, Serialize)]
pub struct AppError(pub String);

impl AppError {
    pub fn msg(m: impl Into<String>) -> Self {
        AppError(m.into())
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError(format!("io: {e}"))
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError(format!("database: {e}"))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError(format!("json: {e}"))
    }
}

impl From<csv::Error> for AppError {
    fn from(e: csv::Error) -> Self {
        AppError(format!("csv: {e}"))
    }
}

impl From<chrono::ParseError> for AppError {
    fn from(e: chrono::ParseError) -> Self {
        AppError(format!("timestamp: {e}"))
    }
}

pub type AppResult<T> = Result<T, AppError>;

/// Run a blocking job off the async runtime thread so the UI stays responsive.
pub async fn blocking<T, F>(job: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> AppResult<T> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(job)
        .await
        .map_err(|e| AppError(format!("worker: {e}")))?
}
