mod cargo;
mod maven;
use std::collections::HashMap;

use cargo::Cargo;
use maven::Maven;
use reqwest::Url;
use tracing::debug;

use crate::{
    common::{purl::Purl, MetadataDependencies},
    VulnLspError,
};
use anyhow::anyhow;

#[derive(Debug, Clone)]
pub(crate) struct ParseContent {
    pub ranges: MetadataDependencies,
    pub transitives: HashMap<Purl, Vec<Purl>>,
}

trait Parser: Send + Sync {
    fn can_parse(&self, url: &Url) -> bool;
    fn parse(&self, document: &str) -> anyhow::Result<ParseContent>;
}

pub struct ParserManager {
    parsers: Vec<Box<dyn Parser>>,
}

impl ParserManager {
    pub fn new() -> Self {
        let parsers = vec![
            Box::new(Cargo::new()) as Box<dyn Parser>,
            Box::new(Maven::new()) as Box<dyn Parser>,
        ];

        Self { parsers }
    }

    pub fn parse(&self, url: &Url, document: &str) -> anyhow::Result<ParseContent> {
        for parser in &self.parsers {
            if parser.can_parse(url) {
                return parser.parse(document);
            }
        }
        debug!("No parser found for {}", url);
        Err(anyhow!(VulnLspError::ParserNotFound(url.clone())))
    }
}
