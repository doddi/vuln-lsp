use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tower_lsp::lsp_types::Url;
use tracing::debug;

use crate::server::purl::Purl;

#[derive(Debug)]
pub struct DocumentStore {
    pub inner: Arc<Mutex<HashMap<Url, StorageItems>>>,
}

#[derive(Debug, Clone)]
pub struct StorageItems {
    pub document: String,
    pub dependencies: MetadataDependencies,
}

pub type BuildDependencies = HashMap<Purl, Vec<Purl>>;
pub type MetadataDependencies = HashMap<PurlRange, Vec<Purl>>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PurlRange {
    pub purl: Purl,
    pub range: Range,
}

impl PurlRange {
    pub fn new(purl: Purl, range: Range) -> Self {
        PurlRange { purl, range }
    }
}

#[derive(Clone, Debug, PartialEq, Default, Eq, Hash)]
pub(crate) struct Range {
    pub start: Position,
    pub end: Position,
}

impl Range {
    pub fn new(start: Position, end: Position) -> Self {
        Range { start, end }
    }
    pub fn contains_position(&self, line_number: usize) -> bool {
        line_number >= self.start.row && line_number <= self.end.row
    }
}

#[derive(Clone, Debug, PartialEq, Default, Eq, Hash)]
pub(crate) struct Position {
    pub row: usize,
    pub col: usize,
}

impl DocumentStore {
    pub fn new() -> Self {
        DocumentStore {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert(&self, url: &Url, content: String, info: MetadataDependencies) {
        let item = StorageItems {
            document: content,
            dependencies: info,
        };

        self.inner.lock().unwrap().insert(url.clone(), item);
    }

    pub fn get(&self, url: &Url) -> Option<StorageItems> {
        self.inner.lock().unwrap().get(url).cloned()
    }

    pub fn get_purl_for_position(&self, url: &Url, line_number: usize) -> Option<Purl> {
        if let Some(items) = self.inner.lock().unwrap().get(url) {
            debug!("Looking for line number: {}", line_number);
            debug!("Purl items: {:?}", items);
            let purl_range = items
                .dependencies
                .iter()
                .find(|item| item.0.range.contains_position(line_number));

            return purl_range.map(|purl_range| purl_range.0.purl.clone());
        }
        None
    }
}
