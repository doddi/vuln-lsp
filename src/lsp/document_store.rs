use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tower_lsp::lsp_types::Url;

#[derive(Debug)]
pub struct DocumentStore {
    pub inner: Arc<Mutex<HashMap<Url, StorageItems>>>,
}

#[derive(Debug, Clone)]
pub struct StorageItems {
    pub document: String,
}

impl DocumentStore {
    pub fn new() -> Self {
        DocumentStore {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert(&self, url: &Url, content: String) {
        let item = StorageItems { document: content };

        self.inner.lock().unwrap().insert(url.clone(), item);
    }

    pub fn get(&self, url: &Url) -> Option<StorageItems> {
        self.inner.lock().unwrap().get(url).cloned()
    }
}
