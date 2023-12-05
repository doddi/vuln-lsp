use log::debug;
use lsp::document_store::{self, DocumentStore};
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
use tracing::{info, warn};

use crate::{lsp::diagnostics, server::purl::Purl};

mod lsp;
mod pom;
pub mod server;

pub async fn start(server_type: VulnerableServerType) {
    let server = create_server(server_type);
    let document_store = document_store::DocumentStore::new();

    let (service, socket) =
        LspService::build(|client| Backend::new(client, server, document_store)).finish();
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
    document_store: DocumentStore,
    server: Box<dyn VulnerabilityServer>,
}

impl Backend {
    pub fn new(
        client: Client,
        server: Box<dyn VulnerabilityServer>,
        document_store: DocumentStore,
    ) -> Self {
        Backend {
            client,
            document_store,
            server,
        }
    }

    async fn generate_hover_content(&self, purl: Purl) -> lsp_types::HoverContents {
        let component_info = self
            .server
            .get_component_information(vec![purl.clone()])
            .await
            .unwrap();

        if component_info.is_empty() {
            return lsp_types::HoverContents::Scalar(lsp_types::MarkedString::String(
                "No information found".to_string(),
            ));
        }

        if let Some(vulnerability) = component_info[0]
            .find_highest_severity_vulnerability(&component_info[0].vulnerabilities)
        {
            lsp_types::HoverContents::Markup(lsp_types::MarkupContent {
                kind: lsp_types::MarkupKind::Markdown,
                value: format!(
                    r#"pkg:{}/{}/{}@{}
                Severity: {:?}
                {}
                {}
                "#,
                    component_info[0].purl.package,
                    component_info[0].purl.group_id,
                    component_info[0].purl.artifact_id,
                    component_info[0].purl.version,
                    vulnerability.severity,
                    vulnerability.summary,
                    vulnerability.detail,
                ),
            })
        } else {
            lsp_types::HoverContents::Scalar(lsp_types::MarkedString::String(
                "No information found".to_string(),
            ))
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(
        &self,
        _params: InitializeParams,
    ) -> tower_lsp::jsonrpc::Result<InitializeResult> {
        info!("Initializing vuln-lsp");

        // TODO Vulnerability servers such as OSSIndex do not support an API endpoint to fetch versions
        // so we need to disable CompletionProvider
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

        debug!("Calculating purls");

        let ranged_purls =
            pom::parser::calculate_dependencies_with_range(&params.text_document.text);
        debug!("Purls: {:?}", ranged_purls);

        self.document_store.insert(
            &params.text_document.uri,
            params.text_document.text,
            ranged_purls,
        );

        let ranged_purls = self.document_store.get(&params.text_document.uri).unwrap();

        let purls: Vec<Purl> = ranged_purls
            .purls
            .iter()
            .map(|ranged| ranged.purl.clone())
            .collect();

        if let Ok(vulnerabilities) = self.server.get_component_information(purls).await {
            debug!("Vulnerabilities: {:?}", vulnerabilities);

            let diagnostics: Vec<Diagnostic> =
                diagnostics::calculate_diagnostics_for_vulnerabilities(
                    ranged_purls.purls,
                    vulnerabilities,
                );

            debug!("Diagnostics: {:?}", diagnostics);
            self.client
                .publish_diagnostics(params.text_document.uri, diagnostics, None)
                .await;
        }
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        // TODO Dont enable this until the backend servers have caching
        return;
        info!("doc changed {}", params.text_document.uri);

        let ranged_purls =
            pom::parser::calculate_dependencies_with_range(&params.content_changes[0].text);
        debug!("Purls: {:?}", ranged_purls);

        self.document_store.insert(
            &params.text_document.uri,
            params.content_changes[0].text.clone(),
            ranged_purls,
        );

        match pom::parser::get_dependencies(&params.content_changes[0].text.clone()) {
            Ok(dependencies) => {
                let purls = dependencies
                    .into_iter()
                    .map(|dep| dep.into())
                    .collect::<Vec<_>>();

                // TODO provide feedback through disgnostics message
                let _response = self.server.get_component_information(purls).await.unwrap();
            }
            Err(err) => debug!("Failed to parse dependencies: {}", err),
        };
    }

    async fn completion(
        &self,
        params: lsp_types::CompletionParams,
    ) -> tower_lsp::jsonrpc::Result<Option<lsp_types::CompletionResponse>> {
        let url = params.text_document_position.text_document.uri;

        let content = self.document_store.get(&url);

        match content {
            Some(items) => match params.context {
                Some(CompletionContext {
                    trigger_kind: CompletionTriggerKind::TRIGGER_CHARACTER,
                    ..
                })
                | Some(CompletionContext {
                    trigger_kind: CompletionTriggerKind::INVOKED,
                    ..
                }) => {
                    let line_position = params.text_document_position.position.line;

                    if pom::parser::is_editing_version(&items.document, line_position as usize) {
                        debug!("Fetching purl");
                        match pom::parser::get_purl(&items.document, line_position as usize) {
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
        let line_number = params.text_document_position_params.position.line;
        let uri = params.text_document_position_params.text_document.uri;

        info!("Hovering over line: {}", line_number);
        match self
            .document_store
            .get_purl_for_position(&uri, line_number as usize)
        {
            Some(purl) => tower_lsp::jsonrpc::Result::Ok(Some(lsp_types::Hover {
                contents: self.generate_hover_content(purl).await,
                range: None,
            })),
            None => {
                warn!("No purl found for position");
                tower_lsp::jsonrpc::Result::Err(tower_lsp::jsonrpc::Error::method_not_found())
            }
        }
    }
}
