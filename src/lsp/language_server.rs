use reqwest::Url;
use tower_lsp::{
    lsp_types::{
        self, CompletionContext, CompletionTriggerKind, Diagnostic, DidChangeTextDocumentParams,
        DidOpenTextDocumentParams, InitializeParams, InitializeResult, InitializedParams,
        ServerCapabilities, ServerInfo, TextDocumentSyncCapability, TextDocumentSyncKind,
    },
    Client, LanguageServer,
};
use tracing::{debug, info, trace, warn};

use crate::{
    lsp::{self, diagnostics},
    parsers::ParserManager,
    server::{cacher::Cacher, purl::Purl, VulnerabilityServer, VulnerabilityVersionInfo},
};

use super::document_store::DocumentStore;

pub(crate) struct Backend {
    client: Client,
    document_store: DocumentStore,
    server: Box<dyn VulnerabilityServer>,
    parser_manager: ParserManager,
    cacher: Cacher<Purl, VulnerabilityVersionInfo>,
}

impl Backend {
    pub fn new(
        client: Client,
        server: Box<dyn VulnerabilityServer>,
        document_store: DocumentStore,
        parser_manager: ParserManager,
    ) -> Self {
        Backend {
            client,
            document_store,
            server,
            parser_manager,
            cacher: Cacher::new(),
        }
    }

    fn cache_new_found_values(&self, vulnerabilities: &[VulnerabilityVersionInfo]) {
        vulnerabilities.iter().for_each(|vulnerability| {
            self.cacher
                .put(vulnerability.purl.clone(), vulnerability.clone())
        });
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
                    r#"{}
                Severity: {:?}
                {}
                {}
                "#,
                    component_info[0].purl,
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

    async fn update_diagnostics(&self, uri: &Url, document: &str) {
        trace!("Updating diagnostics for {}", uri);
        if let Ok(metadata_dependencies) = self.parser_manager.parse(uri, document) {
            trace!("Parsed purls: {:?}", metadata_dependencies);

            self.document_store
                .insert(uri, document.to_owned(), metadata_dependencies);

            trace!("Document store: {:?}", self.document_store);
            let stored_items = self.document_store.get(uri).unwrap();

            trace!("Found {} RangedPurls", stored_items.dependencies.len());

            // Get all the purls for the project in a single vec
            let mut purls: Vec<Purl> = vec![];
            for ele in &stored_items.dependencies {
                purls.extend(ele.1.clone());
            }

            let not_found_keys = self.cacher.find_not_found_keys(&purls);
            trace!("{} purls are not currently cached", not_found_keys.len());

            if not_found_keys.is_empty() {
                debug!("All requested purls found in cache");
            } else if let Ok(vulnerabilities) =
                self.server.get_component_information(not_found_keys).await
            {
                self.cache_new_found_values(&vulnerabilities);
                trace!("New Vulnerabilities cached: {:?}", vulnerabilities);
            }

            if let Some(cached_entries) = self.cacher.get(&purls) {
                let vulnerabilities = cached_entries.values().collect::<Vec<_>>();

                let diagnostics: Vec<Diagnostic> =
                    diagnostics::calculate_diagnostics_for_vulnerabilities(
                        &stored_items,
                        vulnerabilities,
                    );
                trace!("Diagnostics: {:?}", diagnostics);
                self.client
                    .publish_diagnostics(uri.clone(), diagnostics, None)
                    .await;
            }
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

        // TODO: Vulnerability servers such as OSSIndex do not support an API endpoint to fetch versions
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
                    resolve_provider: Some(true),
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

        let uri = params.text_document.uri;
        let text_document = &params.text_document.text;

        self.update_diagnostics(&uri, text_document).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        info!("doc changed {}", params.text_document.uri);

        let uri = params.text_document.uri;
        let text_document = &params.content_changes[0].text;

        self.update_diagnostics(&uri, text_document).await;
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

                    if self.parser_manager.is_editing_version(
                        &url,
                        &items.document,
                        line_position as usize,
                    ) {
                        match self.parser_manager.get_purl(
                            &url,
                            &items.document,
                            line_position as usize,
                        ) {
                            Some(purl) => {
                                debug!("PURL: {:?}", purl);
                                match self.server.get_versions_for_purl(purl).await {
                                    Ok(response) => {
                                        Ok(Some(lsp::completion::build_initial_response(response)))
                                    }
                                    // TODO: Add better error handling
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
                // TODO: Should probably send back an error as the document should always be known
                Ok(None)
            }
        }
    }

    async fn completion_resolve(
        &self,
        params: lsp_types::CompletionItem,
    ) -> tower_lsp::jsonrpc::Result<lsp_types::CompletionItem> {
        debug!("completion_resolve: {:?}", params);
        let data = params.data.unwrap();
        let purl = serde_json::from_value(data).unwrap();

        debug!("about to lookup completion for {}", purl);
        match self.server.get_component_information(vec![purl]).await {
            Ok(vulnerabilities) => Ok(lsp::completion::build_response(&vulnerabilities[0])),
            Err(_) => {
                debug!("Failed to get component information");
                Err(tower_lsp::jsonrpc::Error::internal_error())
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
                contents: self.generate_hover_content(purl.clone()).await,
                range: None,
            })),
            None => {
                warn!("No purl found for position");
                tower_lsp::jsonrpc::Result::Err(tower_lsp::jsonrpc::Error::method_not_found())
            }
        }
    }
}
