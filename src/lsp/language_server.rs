use std::collections::HashMap;

use reqwest::Url;
use tower_lsp::{
    lsp_types::{
        self, Diagnostic, DidChangeTextDocumentParams, DidOpenTextDocumentParams, InitializeParams,
        InitializeResult, InitializedParams, ServerCapabilities, ServerInfo,
        TextDocumentSyncCapability, TextDocumentSyncKind,
    },
    Client, LanguageServer,
};
use tracing::{debug, info, trace};

use crate::{
    common::{document_store::DocumentStore, purl::Purl},
    lsp::diagnostics,
    parsers::{ParseContent, ParserManager},
    server::{VulnerabilityServer, VulnerabilityVersionInfo},
};

use super::hover::create_hover_message;

pub(crate) struct VulnerabilityLanguageServer {
    client: Client,
    document_store: DocumentStore<Url, String>,
    parsed_store: DocumentStore<Url, ParseContent>,
    vuln_store: DocumentStore<Purl, VulnerabilityVersionInfo>,
    server: Box<dyn VulnerabilityServer>,
    parser_manager: ParserManager,
}

impl VulnerabilityLanguageServer {
    pub fn new(
        client: Client,
        server: Box<dyn VulnerabilityServer>,
        document_store: DocumentStore<Url, String>,
        parsed_store: DocumentStore<Url, ParseContent>,
        vuln_store: DocumentStore<Purl, VulnerabilityVersionInfo>,
        parser_manager: ParserManager,
    ) -> Self {
        VulnerabilityLanguageServer {
            client,
            document_store,
            parsed_store,
            server,
            parser_manager,
            vuln_store,
        }
    }

    fn cache_new_found_values(&self, vulnerabilities: Vec<VulnerabilityVersionInfo>) {
        vulnerabilities.into_iter().for_each(|vulnerability| {
            self.vuln_store
                .insert(&vulnerability.purl.clone(), vulnerability)
        });
    }

    async fn generate_hover_content(&self, purl: Purl) -> lsp_types::HoverContents {
        if let Ok(component_info) = self
            .server
            .get_component_information(vec![purl.clone()])
            .await
        {
            if let Some(value) = create_hover_message(component_info) {
                return value;
            }
        }

        lsp_types::HoverContents::Scalar(lsp_types::MarkedString::String(
            "No information found".to_string(),
        ))
    }

    async fn update_diagnostics(&self, uri: &Url) {
        if let Some(document) = self.document_store.get(uri) {
            trace!("Updating diagnostics for {}", uri);
            if let Ok(parsed_content) = self.parser_manager.parse(uri, &document) {
                self.parsed_store.insert(uri, parsed_content);
                if let Some(parsed_content) = self.parsed_store.get(uri) {
                    let vals = parsed_content.transitives.clone().into_values();
                    let flattened_dependencies: Vec<Purl> = vals.flatten().collect();
                    let dependencies = &flattened_dependencies[..];

                    let unknown_purls = self.get_purls_from_vuln_store(dependencies);
                    trace!("{} purls are not currently cached", unknown_purls.len());
                    self.fetch_and_cache_vulnerabilities(unknown_purls).await;

                    let cached_entries = self.get_items_from_vuln_store(dependencies);
                    let vulnerabilities = cached_entries.values().collect::<Vec<_>>();
                    let diagnostics: Vec<Diagnostic> =
                        diagnostics::calculate_diagnostics_for_vulnerabilities(
                            parsed_content,
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

    fn get_purl_position_in_document(&self, url: &Url, line_number: usize) -> Option<Purl> {
        trace!("getting document for for generating hover");
        if let Some(parsed_content) = self.parsed_store.get(url) {
            trace!("found document for for generating hover");
            for (purl, range) in parsed_content.ranges.iter() {
                trace!("looking for {} in {:?}", line_number, range);
                if range.contains_position(line_number) {
                    return Some(purl.clone());
                }
            }
        }
        None
    }

    async fn fetch_and_cache_vulnerabilities(&self, purls: Vec<Purl>) {
        if purls.is_empty() {
            debug!("All requested purls found in cache");
        } else if let Ok(vulnerabilities) = self.server.get_component_information(purls).await {
            // Filter out any responses that have empty vulnerability information
            let vulnerabilities = vulnerabilities
                .into_iter()
                .filter(|v| !v.vulnerabilities.is_empty())
                .collect::<Vec<_>>();
            self.cache_new_found_values(vulnerabilities);
        }
    }

    fn get_purls_from_vuln_store(&self, dependencies: &[Purl]) -> Vec<Purl> {
        dependencies
            .iter()
            .filter(|dependency| self.vuln_store.get(dependency).is_none())
            .cloned()
            .collect::<Vec<Purl>>()
    }

    fn get_items_from_vuln_store(
        &self,
        dependencies: &[Purl],
    ) -> HashMap<Purl, VulnerabilityVersionInfo> {
        dependencies
            .iter()
            .filter(|dependency| self.vuln_store.get(dependency).is_some())
            .map(|purl| {
                let vuln = self.vuln_store.get(purl).unwrap();
                (purl.clone(), vuln)
            })
            .collect()
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for VulnerabilityLanguageServer {
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
        let text_document = params.text_document.text;

        self.document_store.insert(&uri, text_document);
        self.update_diagnostics(&uri).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        info!("doc changed {}", params.text_document.uri);

        let uri = params.text_document.uri;

        if !params.content_changes.is_empty() {
            let text_document = params.content_changes[0].text.clone();
            self.document_store.insert(&uri, text_document);
        }
    }

    async fn did_save(&self, params: lsp_types::DidSaveTextDocumentParams) {
        info!("doc saved: {}", params.text_document.uri);

        let uri = params.text_document.uri;
        info!("has changes {}", params.text.is_some());
        info!("about to update diagnostics");
        self.update_diagnostics(&uri).await;
    }

    // async fn completion(
    //     &self,
    //     params: lsp_types::CompletionParams,
    // ) -> tower_lsp::jsonrpc::Result<Option<lsp_types::CompletionResponse>> {
    //     let url = params.text_document_position.text_document.uri;
    //
    //     let content = self.document_store.get(&url);
    //
    //     match content {
    //         Some(items) => match params.context {
    //             Some(CompletionContext {
    //                 trigger_kind: CompletionTriggerKind::TRIGGER_CHARACTER,
    //                 ..
    //             })
    //             | Some(CompletionContext {
    //                 trigger_kind: CompletionTriggerKind::INVOKED,
    //                 ..
    //             }) => {
    //                 let line_position = params.text_document_position.position.line;
    //
    //                 if self.parser_manager.is_editing_version(
    //                     &url,
    //                     &items.document,
    //                     line_position as usize,
    //                 ) {
    //                     match self.parser_manager.get_purl(
    //                         &url,
    //                         &items.document,
    //                         line_position as usize,
    //                     ) {
    //                         Some(purl) => {
    //                             debug!("PURL: {:?}", purl);
    //                             match self.server.get_versions_for_purl(purl).await {
    //                                 Ok(response) => {
    //                                     Ok(Some(lsp::completion::build_initial_response(response)))
    //                                 }
    //                                 // TODO: Add better error handling
    //                                 Err(_) => Ok(None),
    //                             }
    //                         }
    //                         None => todo!(),
    //                     }
    //                 } else {
    //                     Ok(None)
    //                 }
    //             }
    //             _ => Ok(None),
    //         },
    //         None => {
    //             warn!("Document not found");
    //             // TODO: Should probably send back an error as the document should always be known
    //             Ok(None)
    //         }
    //     }
    // }
    //
    // async fn completion_resolve(
    //     &self,
    //     params: lsp_types::CompletionItem,
    // ) -> tower_lsp::jsonrpc::Result<lsp_types::CompletionItem> {
    //     debug!("completion_resolve: {:?}", params);
    //     let data = params.data.unwrap();
    //     let purl = serde_json::from_value(data).unwrap();
    //
    //     debug!("about to lookup completion for {}", purl);
    //     match self.server.get_component_information(vec![purl]).await {
    //         Ok(vulnerabilities) => Ok(lsp::completion::build_response(&vulnerabilities[0])),
    //         Err(_) => {
    //             debug!("Failed to get component information");
    //             Err(tower_lsp::jsonrpc::Error::internal_error())
    //         }
    //     }
    // }

    async fn hover(
        &self,
        params: lsp_types::HoverParams,
    ) -> tower_lsp::jsonrpc::Result<Option<lsp_types::Hover>> {
        let line_number = params.text_document_position_params.position.line;
        let uri = params.text_document_position_params.text_document.uri;

        trace!("Hovering over line: {}", line_number);
        if let Some(purl) = self.get_purl_position_in_document(&uri, line_number as usize) {
            Ok(Some(lsp_types::Hover {
                contents: self.generate_hover_content(purl.clone()).await,
                range: None,
            }))
        } else {
            Ok(None)
        }
    }
}
