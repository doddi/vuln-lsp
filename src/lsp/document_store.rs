use std::collections::HashMap;

use tower_lsp::lsp_types::Url;

#[derive(Debug, Default)]
pub struct DocumentStore {
    pub documents: HashMap<Url, String>,
}

impl DocumentStore {
    pub fn insert(&mut self, url: &Url, document: String) {
        self.documents.insert(url.clone(), document);
    }

    pub fn get(&self, url: &Url) -> Option<String> {
        self.documents.get(url).cloned()
    }
}
