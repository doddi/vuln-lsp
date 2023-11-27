use serde::{Deserialize, Serialize};

pub mod lsp;
pub mod pom;
pub mod vulnerability_server;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Purl {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
}
