use std::sync::{Arc, Mutex};

use log::debug;
use lsp::document_store;
use server::{VulnerabilityServer, VulnerableServerType};
use tokio::io::{stdin, stdout};
use tower_lsp::{
    lsp_types::{
        self, CompletionContext, CompletionTriggerKind, Diagnostic, DidChangeTextDocumentParams,
        DidOpenTextDocumentParams, InitializeParams, InitializeResult, InitializedParams,
        ServerCapabilities, ServerInfo, TextDocumentSyncCapability, TextDocumentSyncKind,
    },
    Client, LanguageServer, LspService, Server,
};
use tracing::{error, info, warn};

use crate::{lsp::diagnostics, server::purl::Purl};

mod lsp;
mod pom;
pub mod server;

pub async fn start(server_type: VulnerableServerType) {
    let (service, socket) =
        LspService::build(|client| Backend::new(client, create_server(server_type))).finish();
    Server::new(stdin(), stdout(), socket).serve(service).await;
}

fn create_server(server_type: VulnerableServerType) -> Box<dyn VulnerabilityServer> {
    match server_type {
        VulnerableServerType::Dummy => Box::new(server::dummy::Dummy {}),
        VulnerableServerType::OssIndex => Box::new(server::ossindex::OssIndex {
            client: reqwest::Client::new(),
        }),
    }
}

struct Backend {
    client: Client,
    document_store: Arc<Mutex<document_store::DocumentStore>>,
    server: Box<dyn VulnerabilityServer>,
}

impl Backend {
    pub fn new(client: Client, server: Box<dyn VulnerabilityServer>) -> Self {
        Backend {
            client,
            document_store: Arc::new(Mutex::new(document_store::DocumentStore::default())),
            server,
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(
        &self,
        _params: InitializeParams,
    ) -> tower_lsp::jsonrpc::Result<InitializeResult> {
        info!("Initializing");

        Ok(InitializeResult {
            server_info: Some(ServerInfo {
                name: "vuln-lsp".to_string(),
                version: None,
            }),
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                completion_provider: Some(lsp_types::CompletionOptions {
                    resolve_provider: Some(false),
                    trigger_characters: Some(vec![">".to_string()]),
                    work_done_progress_options: Default::default(),
                    all_commit_characters: None,
                    completion_item: None,
                }),
                hover_provider: Some(lsp_types::HoverProviderCapability::Simple(true)),
                ..ServerCapabilities::default()
            },
            offset_encoding: None,
        })
    }

    async fn initialized(&self, _params: InitializedParams) {
        debug!("Initialized");
    }

    async fn shutdown(&self) -> tower_lsp::jsonrpc::Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        debug!("doc opened {}", params.text_document.uri);

        self.document_store
            .lock()
            .unwrap()
            .insert(&params.text_document.uri, params.text_document.text.clone());

        debug!("Calculating purls");

        let ranged_purls =
            pom::parser::calculate_dependencies_with_range(&params.text_document.text);

        debug!("Purls: {:?}", ranged_purls);

        let purls: Vec<Purl> = ranged_purls
            .iter()
            .map(|ranged| ranged.purl.clone())
            .collect();

        if let Ok(vulnerabilities) = self.server.get_component_information(purls).await {
            debug!("Vulnerabilities: {:?}", vulnerabilities);

            let diagnostics: Vec<Diagnostic> =
                diagnostics::calculate_diagnostics_for_vulnerabilities(
                    ranged_purls,
                    vulnerabilities,
                );

            debug!("Found {} diagnostic vulnerabilities", diagnostics.len());
            debug!("Diagnostics: {:?}", diagnostics);
            self.client
                .publish_diagnostics(params.text_document.uri, diagnostics, None)
                .await;
        }
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        info!("doc changed {}", params.text_document.uri);

        self.document_store.lock().unwrap().insert(
            &params.text_document.uri,
            params.content_changes[0].text.clone(),
        );

        match pom::parser::get_dependencies(&params.content_changes[0].text.clone()) {
            Ok(dependencies) => {
                let purls = dependencies
                    .into_iter()
                    .map(|dep| dep.into())
                    .collect::<Vec<_>>();

                // TODO provide feedback through disgnostics message
                let response = self.server.get_component_information(purls).await.unwrap();
            }
            Err(err) => debug!("Failed to parse dependencies: {}", err),
        };
    }

    async fn completion(
        &self,
        params: lsp_types::CompletionParams,
    ) -> tower_lsp::jsonrpc::Result<Option<lsp_types::CompletionResponse>> {
        let url = params.text_document_position.text_document.uri;

        let content = self.document_store.lock().unwrap().get(&url);

        match content {
            Some(document) => match params.context {
                Some(CompletionContext {
                    trigger_kind: CompletionTriggerKind::TRIGGER_CHARACTER,
                    ..
                })
                | Some(CompletionContext {
                    trigger_kind: CompletionTriggerKind::INVOKED,
                    ..
                }) => {
                    let line_position = params.text_document_position.position.line;

                    if pom::parser::is_editing_version(&document, line_position as usize) {
                        debug!("Fetching purl");
                        match pom::parser::get_purl(&document, line_position as usize) {
                            Some(purl) => {
                                info!("PURL: {:?}", purl);
                                match self.server.get_versions_for_purl(purl).await {
                                    Ok(response) => {
                                        Ok(Some(lsp::completion::build_response(response)))
                                    }
                                    // TODO Add better error handling
                                    Err(_) => Ok(None),
                                }
                            }
                            None => todo!(),
                        }
                    } else {
                        Ok(None)
                    }
                }
                _ => Ok(None),
            },
            None => {
                warn!("Document not found");
                // TODO Should probably send back an error as the document should always be known
                Ok(None)
            }
        }
    }

    async fn hover(
        &self,
        params: lsp_types::HoverParams,
    ) -> tower_lsp::jsonrpc::Result<Option<lsp_types::Hover>> {
        let _ = params;
        error!("Got a textDocument/hover request, but it is not implemented");
        tower_lsp::jsonrpc::Result::Err(tower_lsp::jsonrpc::Error::method_not_found())
    }
}
