use iq_lsp::lsp::document_store::{self};
use iq_lsp::{lsp, pom, vulnerability_server};
use log::{debug, info};
use std::fs::File;
use std::sync::Mutex;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::{
    CompletionContext, CompletionItem, CompletionItemKind, CompletionResponse,
    CompletionTriggerKind, Diagnostic, DidChangeTextDocumentParams, DidOpenTextDocumentParams,
    Documentation, InitializeParams, InitializeResult, InitializedParams, Range,
    ServerCapabilities, ServerInfo, TextDocumentSyncCapability, TextDocumentSyncKind, Url,
};
use tower_lsp::{lsp_types, Client, LanguageServer, LspService, Server};
use tracing::warn;
use tracing_subscriber::EnvFilter;

#[derive(Debug)]
struct Backend {
    client: Client,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Backend { client }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _params: InitializeParams) -> Result<InitializeResult> {
        info!("Initializing");

        Ok(InitializeResult {
            server_info: Some(ServerInfo {
                name: "iq-lsp".to_string(),
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
                ..ServerCapabilities::default()
            },
            offset_encoding: None,
        })
    }

    async fn initialized(&self, _params: InitializedParams) {
        debug!("Initialized");
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        debug!("doc opened {}", params.text_document.uri);
        document_store::set_stored_document(
            params.text_document.uri,
            params.text_document.text.clone(),
        );
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        info!("doc changed {}", params.text_document.uri);

        document_store::set_stored_document(
            params.text_document.uri,
            params.content_changes[0].text.clone(),
        );
    }

    async fn completion(
        &self,
        params: lsp_types::CompletionParams,
    ) -> Result<Option<lsp_types::CompletionResponse>> {
        let url = params.text_document_position.text_document.uri;

        match document_store::get_stored_document(&url) {
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
                                let versions_available =
                                    vulnerability_server::get_version_information_for_purl(&purl)
                                        .await;
                                Ok(Some(lsp::build_response(versions_available)))
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
}

// TODO Add arguments so that tracing can be configured and also to pass `stdio`
#[tokio::main]
async fn main() {
    let log_file = File::create("/tmp/trace.log").expect("should create trace file");
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(Mutex::new(log_file))
        .init();

    let (stdin, stdout) = (tokio::io::stdin(), tokio::io::stdout());

    let (service, socket) = LspService::build(|client| Backend::new(client)).finish();
    Server::new(stdin, stdout, socket).serve(service).await;
}
