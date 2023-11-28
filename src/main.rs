use log::{debug, info};
use std::fs::File;
use std::sync::{Arc, Mutex};
use tower_lsp::jsonrpc::Result;
use tower_lsp::{
    lsp_types::{
        self, CompletionContext, CompletionTriggerKind, Diagnostic, DidChangeTextDocumentParams,
        DidOpenTextDocumentParams, InitializeParams, InitializeResult, InitializedParams,
        ServerCapabilities, ServerInfo, TextDocumentSyncCapability, TextDocumentSyncKind,
    },
    Client, LanguageServer, LspService, Server,
};
use tracing::warn;
use tracing_subscriber::EnvFilter;
use vuln_lsp::lsp::diagnostics;
use vuln_lsp::lsp::document_store::{self};
use vuln_lsp::server::purl::Purl;
use vuln_lsp::{lsp, pom, server};

#[derive(Debug)]
struct Backend {
    client: Client,
    document_store: Arc<Mutex<document_store::DocumentStore>>,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Backend {
            client,
            document_store: Arc::new(Mutex::new(document_store::DocumentStore::default())),
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _params: InitializeParams) -> Result<InitializeResult> {
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

        let vulnerabilities = server::get_vulnerability_information_for_purls(purls).await;

        debug!("Vulnerabilities: {:?}", vulnerabilities);

        let disgnostics: Vec<Diagnostic> =
            diagnostics::calculate_diagnostics_for_vulnerabilities(ranged_purls, vulnerabilities);

        self.client
            .publish_diagnostics(&params.text_document.uri, disgnostics, None)
            .await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        info!("doc changed {}", params.text_document.uri);

        self.document_store.lock().unwrap().insert(
            &params.text_document.uri,
            params.content_changes[0].text.clone(),
        );

        match pom::parser::get_dependencies(&params.content_changes[0].text.clone()) {
            Ok(dependencies) => {
                server::get_vulnerability_information_for_purls(
                    dependencies
                        .into_iter()
                        .map(|dep| dep.into())
                        .collect::<Vec<_>>(),
                )
                .await;
            }
            Err(err) => debug!("Failed to parse dependencies: {}", err),
        };
    }

    async fn completion(
        &self,
        params: lsp_types::CompletionParams,
    ) -> Result<Option<lsp_types::CompletionResponse>> {
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
                                let versions_available =
                                    server::get_vulnerability_information_for_purls(vec![purl])
                                        .await;
                                let first_response = versions_available[0].clone();
                                Ok(Some(lsp::completion::build_response(first_response)))
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
