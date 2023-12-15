use lsp::{document_store::DocumentStore, language_server::Backend};
use parsers::ParserManager;
use reqwest::Url;
use server::{VulnerabilityServer, VulnerableServerType};
use thiserror::Error;
use tokio::io::{stdin, stdout};
use tower_lsp::{LspService, Server};

mod lsp;
mod parsers;
pub mod server;

#[derive(Debug, Error)]
pub(crate) enum VulnLspError {
    #[error("Parser not found for {0}")]
    ParserNotFound(Url),
    #[error("Error sending {0} request to backend")]
    ServerRequest(Url),
    #[error("Error parsing backend response")]
    ServerParse,
}

pub async fn start(server_type: VulnerableServerType) {
    let server = create_server(server_type).await;
    let document_store = DocumentStore::new();

    let (service, socket) = LspService::build(|client| {
        Backend::new(client, server, document_store, ParserManager::new())
    })
    .finish();
    Server::new(stdin(), stdout(), socket).serve(service).await;
}

async fn create_server(server_type: VulnerableServerType) -> Box<dyn VulnerabilityServer> {
    match server_type {
        VulnerableServerType::Dummy => Box::new(server::dummy::Dummy {}),
        VulnerableServerType::OssIndex => Box::new(server::ossindex::OssIndex::new()),
        VulnerableServerType::Sonatype(base_url, application) => {
            Box::new(server::sonatype::Sonatype::new(base_url, application).await)
        }
    }
}
