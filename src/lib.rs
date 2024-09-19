use lsp::{language_server::VulnerabilityLanguageServer, progress::ProgressNotifier};
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

pub async fn start(server_type: VulnerableServerType, include_transitives: bool) {
    trace!("Starting LSP server using {:?}", server_type);

    let (service, socket) = LspService::build(|client| {
        let progress_notifier = ProgressNotifier::new(client.clone());
        let server = create_server(&server_type, progress_notifier.clone());
        VulnerabilityLanguageServer::new(
            client,
            server,
            ParserManager::new(include_transitives),
            progress_notifier,
        )
    })
    .finish();
    Server::new(stdin(), stdout(), socket).serve(service).await;
}

fn create_server(
    server_type: &VulnerableServerType,
    progress_notifier: ProgressNotifier,
) -> Box<dyn VulnerabilityServer> {
    match server_type {
        VulnerableServerType::Dummy => Box::new(server::dummy::Dummy {}),
        VulnerableServerType::OssIndex => {
            Box::new(server::ossindex::OssIndex::new(progress_notifier))
        }
        VulnerableServerType::Sonatype { base_url } => Box::new(server::sonatype::Sonatype::new(
            base_url.to_owned(),
            progress_notifier,
        )),
    }
}
