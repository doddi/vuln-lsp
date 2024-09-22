use crate::common::purl::Purl;
use reqwest::Url;
use tower_lsp::{
    lsp_types::{
        self, DidChangeTextDocumentParams, DidOpenTextDocumentParams, InitializeParams,
        InitializeResult, InitializedParams, ServerCapabilities, ServerInfo,
        TextDocumentSyncCapability, TextDocumentSyncKind,
    },
    Client, LanguageServer,
};
use tracing::{debug, info, trace};

use crate::lsp::diagnostics;

use super::{hover, middleware::Middleware, progress::ProgressNotifier};

pub(crate) struct VulnerabilityLanguageServer {
    middleware: Middleware,
    client: Client,
    #[allow(dead_code)]
    progress_notifier: ProgressNotifier,
}

impl VulnerabilityLanguageServer {
    pub fn new(
        middleware: Middleware,
        client: Client,
        progress_notifier: ProgressNotifier,
    ) -> Self {
        VulnerabilityLanguageServer {
            middleware,
            client,
            progress_notifier,
        }
    }

    async fn generate_hover_content(&self, direct_dependency: &Purl) -> lsp_types::HoverContents {
        if let Some((transitive, info)) = self
            .middleware
            .get_calculated_security_information_for_direct_dependency(direct_dependency)
        {
            if direct_dependency == &transitive {
                return hover::create_hover_message(direct_dependency, None, info);
            } else {
                return hover::create_hover_message(direct_dependency, Some(transitive), info);
            }
        }

        lsp_types::HoverContents::Scalar(lsp_types::MarkedString::String(
            "No information found".to_string(),
        ))
    }

    async fn update_diagnostics(&self, uri: &Url) {
        let security_information = self.middleware.get_security_information_for_document(uri);
        if !security_information.is_empty() {
            let diagnostics = security_information
                .iter()
                .map(|(purl_range, item)| diagnostics::create_diagnostic(purl_range, item))
                .collect();

            self.client
                .publish_diagnostics(uri.clone(), diagnostics, None)
                .await;
        }
    }

    async fn update_dependencies(&self, uri: &Url) {
        let _ = self.middleware.update_dependencies(uri).await;
        self.update_diagnostics(uri).await;
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

        self.middleware.store_document(&uri, text_document);

        let _ = self.update_dependencies(&uri).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        info!("doc changed {}", params.text_document.uri);

        let uri = params.text_document.uri;

        if !params.content_changes.is_empty() {
            let text_document = params.content_changes[0].text.clone();
            self.middleware.store_document(&uri, text_document);
        }
    }

    async fn did_save(&self, params: lsp_types::DidSaveTextDocumentParams) {
        info!("doc saved: {}", params.text_document.uri);

        let uri = params.text_document.uri;
        let _ = self.update_dependencies(&uri).await;
    }

    async fn hover(
        &self,
        params: lsp_types::HoverParams,
    ) -> tower_lsp::jsonrpc::Result<Option<lsp_types::Hover>> {
        let line_number = params.text_document_position_params.position.line;
        let uri = params.text_document_position_params.text_document.uri;

        trace!("Hovering over line: {}", line_number);
        if let Some(purl) = self
            .middleware
            .get_purl_position_in_document(&uri, line_number as usize)
        {
            Ok(Some(lsp_types::Hover {
                contents: self.generate_hover_content(&purl).await,
                range: None,
            }))
        } else {
            Ok(None)
        }
    }
}
