use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use tower_lsp::lsp_types::Url;

pub struct DocumentStore {
    pub documents: HashMap<Url, String>,
}

static DOCUMENT_STORE: OnceLock<Arc<Mutex<DocumentStore>>> = OnceLock::new();

pub fn get_stored_document(url: &Url) -> Option<String> {
    let doc = DOCUMENT_STORE
        .get_or_init(|| {
            Arc::new(Mutex::new(DocumentStore {
                documents: HashMap::new(),
            }))
        })
        .lock()
        .unwrap();
    doc.documents.get(url).cloned()
}

pub fn set_stored_document(url: Url, document: String) {
    DOCUMENT_STORE
        .get_or_init(|| {
            Arc::new(Mutex::new(DocumentStore {
                documents: HashMap::new(),
            }))
        })
        .lock()
        .unwrap()
        .documents
        .insert(url, document);
}
