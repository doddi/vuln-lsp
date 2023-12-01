use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tower_lsp::lsp_types::Url;
use tracing::debug;

use crate::server::purl::{Purl, PurlRange};

#[derive(Debug)]
pub struct DocumentStore {
    pub inner: Arc<Mutex<HashMap<Url, StorageItems>>>,
}

#[derive(Debug, Clone)]
pub struct StorageItems {
    pub document: String,
    pub purls: Vec<PurlRange>,
}

impl DocumentStore {
    pub fn new() -> Self {
        DocumentStore {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert(&self, url: &Url, content: String, purls: Vec<PurlRange>) {
        let item = StorageItems {
            document: content,
            purls,
        };

        self.inner.lock().unwrap().insert(url.clone(), item);
    }

    pub fn get(&self, url: &Url) -> Option<StorageItems> {
        self.inner.lock().unwrap().get(url).cloned()
    }

    pub fn get_purl_for_position(&self, url: &Url, line_number: usize) -> Option<Purl> {
        if let Some(items) = self.inner.lock().unwrap().get(url) {
            debug!("Looking for line numver: {}", line_number);
            debug!("Purl items: {:?}", items.purls);
            let purl_range = items
                .purls
                .iter()
                .find(|purl| purl.range.contains_position(line_number));

            return purl_range.map(|purl_range| purl_range.purl.clone());
        }
        None
    }
}
