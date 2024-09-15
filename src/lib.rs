use common::document_store::DocumentStore;
use lsp::language_server::Backend;
use parsers::ParserManager;
use server::{VulnerabilityServer, VulnerableServerType};
use tokio::io::{stdin, stdout};
use tower_lsp::{LspService, Server};
use tracing::trace;

pub(crate) mod common;
pub mod logging;
mod lsp;
mod parsers;
pub mod server;

pub async fn start(server_type: VulnerableServerType, direct_only: bool) {
    let server = create_server(&server_type).await;
    let document_store = DocumentStore::new();
    let parsed_store = DocumentStore::new();
    let vuln_store = DocumentStore::new();

    trace!("Starting LSP server using {:?}", server_type);

    let (service, socket) = LspService::build(|client| {
        Backend::new(
            client,
            server,
            document_store,
            parsed_store,
            vuln_store,
            ParserManager::new(direct_only),
        )
    })
    .finish();
    Server::new(stdin(), stdout(), socket).serve(service).await;
}

async fn create_server(server_type: &VulnerableServerType) -> Box<dyn VulnerabilityServer> {
    match server_type {
        VulnerableServerType::Dummy => Box::new(server::dummy::Dummy {}),
        VulnerableServerType::OssIndex => Box::new(server::ossindex::OssIndex::new()),
        VulnerableServerType::Sonatype { base_url } => {
            Box::new(server::sonatype::Sonatype::new(base_url.to_owned()).await)
        }
    }
}
