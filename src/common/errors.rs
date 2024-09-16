use reqwest::Url;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum VulnLspError {
    #[error("Parser not found for {0}")]
    ParserNotFound(Url),
    #[error("Error parsing {0}")]
    ManifestParse(String),
    #[error("Error generating dependencies {0}")]
    BuildDependency(String),

    #[error("Error sending {0} request to backend")]
    ServerRequest(Url),
    #[error("Error parsing backend response")]
    ServerParse,
    #[error("Server error {0}")]
    ServerError(String),
}
