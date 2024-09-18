use crate::{common::errors::VulnLspError, server::VulnerabilityInformation};
use anyhow::anyhow;
use futures::future;
use reqwest::Url;
use std::collections::HashMap;
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

use super::{
    hover::{self},
    progress::ProgressNotifier,
};

pub(crate) struct VulnerabilityLanguageServer {
    client: Client,
    document_store: DocumentStore<Url, String>,
    parsed_store: DocumentStore<Url, ParseContent>,
    vuln_store: DocumentStore<Purl, VulnerabilityVersionInfo>,
    server: Box<dyn VulnerabilityServer>,
    parser_manager: ParserManager,
    #[allow(dead_code)]
    progress_notifier: ProgressNotifier,
}

impl VulnerabilityLanguageServer {
    pub fn new(
        client: Client,
        server: Box<dyn VulnerabilityServer>,
        document_store: DocumentStore<Url, String>,
        parsed_store: DocumentStore<Url, ParseContent>,
        vuln_store: DocumentStore<Purl, VulnerabilityVersionInfo>,
        parser_manager: ParserManager,
        progress_notifier: ProgressNotifier,
    ) -> Self {
        VulnerabilityLanguageServer {
            client: client.clone(),
            document_store,
            parsed_store,
            server,
            parser_manager,
            vuln_store,
            progress_notifier,
        }
    }

    fn cache_new_found_values(&self, vulnerabilities: Vec<VulnerabilityVersionInfo>) {
        trace!("caching {:?}", vulnerabilities);
        vulnerabilities.into_iter().for_each(|vulnerability| {
            self.vuln_store
                .insert(&vulnerability.purl.clone(), vulnerability)
        });
    }

    async fn generate_hover_content(&self, url: &Url, purl: Purl) -> lsp_types::HoverContents {
        if let Some(parsed_content) = self.parsed_store.get(url) {
            // Get all the vulnerability information associated with the purl and its transitives
            if let Some(all_transitive_purls) = &parsed_content.transitives.get(&purl) {
                let vulnerabilities_for_transitives =
                    self.get_items_from_vuln_store(all_transitive_purls);

                let mut chosen_purl: Option<Purl> = None;
                let mut chosen_vulnerability: Option<VulnerabilityInformation> = None;
                for (purl, vulnerabilities) in vulnerabilities_for_transitives {
                    for vulnerability_information in vulnerabilities.vulnerabilities {
                        // TODO: This is ugly, should be relying on ordering of the strut
                        match chosen_vulnerability {
                            None => {
                                chosen_purl = Some(purl.clone());
                                chosen_vulnerability = Some(vulnerability_information.clone());
                            }
                            Some(ref value) => {
                                match value.severity.cmp(&vulnerability_information.severity) {
                                    std::cmp::Ordering::Less => {}
                                    std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {
                                        chosen_purl = Some(purl.clone());
                                        chosen_vulnerability =
                                            Some(vulnerability_information.clone());
                                    }
                                };
                            }
                        }
                    }
                }

                if chosen_purl.is_some() {
                    if let Some(vulnerability) = chosen_vulnerability {
                        return hover::create_hover_message(&purl, chosen_purl, vulnerability);
                    }
                }
            }
        }

        lsp_types::HoverContents::Scalar(lsp_types::MarkedString::String(
            "No information found".to_string(),
        ))
    }

    async fn check_dependencies(&self, uri: &Url) -> anyhow::Result<bool> {
        if let Some(document) = self.document_store.get(uri) {
            trace!("Updating dependencies for {}", uri);

            let parsed_content = self.parser_manager.parse(uri, &document)?;
            self.parsed_store.insert(uri, parsed_content);
            if let Some(parsed_content) = self.parsed_store.get(uri) {
                let vals = parsed_content.transitives.clone().into_values();
                let flattened_dependencies: Vec<Purl> = vals.flatten().collect();
                let dependencies = &flattened_dependencies[..];

                trace!("{:?}", dependencies);
                let unknown_purls = self.get_missing_purls_from_vuln_store(dependencies);
                trace!(
                    "There are {} purls not currently cached",
                    unknown_purls.len()
                );

                self.fetch_and_cache_vulnerabilities(&unknown_purls).await;
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn update_diagnostics(&self, uri: &Url) {
        if let Some(parsed_content) = self.parsed_store.get(uri) {
            trace!("found content");
            let vals = parsed_content.transitives.clone().into_values();
            let flattened_dependencies: Vec<Purl> = vals.flatten().collect();
            let dependencies = &flattened_dependencies[..];

            let cached_entries = self.get_items_from_vuln_store(dependencies);
            trace!("cached_entries");
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

    fn get_purl_position_in_document(&self, url: &Url, line_number: usize) -> Option<Purl> {
        if let Some(parsed_content) = self.parsed_store.get(url) {
            for (purl, range) in parsed_content.ranges.iter() {
                if range.contains_position(line_number) {
                    return Some(purl.clone());
                }
            }
        }
        None
    }

    async fn batch(&self, purls: &[Purl]) -> anyhow::Result<Vec<VulnerabilityVersionInfo>> {
        const BATCH_SIZE: usize = 100;
        let chunks = purls.chunks(BATCH_SIZE);
        info!("Request is split into {} chunks", chunks.len());

        // TODO: How can I keep a counter updated?
        let joins = chunks
            .into_iter()
            .map(|chunk| self.server.get_component_information(chunk));

        match future::try_join_all(joins.into_iter()).await {
            Ok(results) => Ok(results
                .into_iter()
                .flatten()
                .collect::<Vec<VulnerabilityVersionInfo>>()),
            Err(_err) => Err(anyhow!(VulnLspError::ServerError(
                "Error requesting batches".to_string()
            ))),
        }
    }

    async fn fetch_and_cache_vulnerabilities(&self, purls: &[Purl]) {
        if purls.is_empty() {
            debug!("All requested purls found in cache");
        } else if let Ok(vulnerabilities) = self.batch(purls).await {
            // Filter out any responses that have empty vulnerability information
            let vulnerabilities = vulnerabilities
                .into_iter()
                .filter(|v| !v.vulnerabilities.is_empty())
                .collect::<Vec<_>>();
            self.cache_new_found_values(vulnerabilities);
        }
    }

    fn get_missing_purls_from_vuln_store(&self, dependencies: &[Purl]) -> Vec<Purl> {
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
        if let Ok(result) = self.check_dependencies(&uri).await {
            if result {
                self.update_diagnostics(&uri).await;
            }
        }
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
        if let Ok(result) = self.check_dependencies(&uri).await {
            if result {
                self.update_diagnostics(&uri).await;
            }
        }
    }

    async fn hover(
        &self,
        params: lsp_types::HoverParams,
    ) -> tower_lsp::jsonrpc::Result<Option<lsp_types::Hover>> {
        let line_number = params.text_document_position_params.position.line;
        let uri = params.text_document_position_params.text_document.uri;

        trace!("Hovering over line: {}", line_number);
        if let Some(purl) = self.get_purl_position_in_document(&uri, line_number as usize) {
            Ok(Some(lsp_types::Hover {
                contents: self.generate_hover_content(&uri, purl.clone()).await,
                range: None,
            }))
        } else {
            Ok(None)
        }
    }
}
