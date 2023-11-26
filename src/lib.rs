pub mod lsp;
pub mod pom;
pub mod vulnerability_server;

#[derive(Debug)]
pub struct Purl {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
}
