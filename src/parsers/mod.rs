mod cargo;
mod pom;
use reqwest::Url;
use tracing::debug;

use crate::{lsp::document_store::MetadataDependencies, server::purl::Purl, VulnLspError};
use anyhow::anyhow;

trait Parser: Send + Sync {
    fn can_parse(&self, url: &Url) -> bool;
    fn parse(&self, document: &str) -> anyhow::Result<MetadataDependencies>;

    fn is_editing_version(&self, document: &str, line_position: usize) -> bool;
    fn get_purl(&self, document: &str, line_position: usize) -> Option<Purl>;
}

pub struct ParserManager {
    parsers: Vec<Box<dyn Parser>>,
}

fn create_pom_parser() -> Box<dyn Parser> {
    Box::new(pom::parser::PomParser {})
}

fn create_cargo_parser() -> Box<dyn Parser> {
    Box::new(cargo::CargoParser {})
}

impl ParserManager {
    pub fn new() -> Self {
        let parsers = vec![create_pom_parser(), create_cargo_parser()];

        Self { parsers }
    }

    pub fn parse(&self, url: &Url, document: &str) -> anyhow::Result<MetadataDependencies> {
        for parser in &self.parsers {
            if parser.can_parse(url) {
                return parser.parse(document);
            }
        }
        debug!("No parser found for {}", url);
        Err(anyhow!(VulnLspError::ParserNotFound(url.clone())))
    }

    pub fn is_editing_version(&self, url: &Url, document: &str, line_position: usize) -> bool {
        for parser in &self.parsers {
            if parser.can_parse(url) {
                return parser.is_editing_version(document, line_position);
            }
        }
        false
    }

    pub fn get_purl(&self, url: &Url, document: &str, line_position: usize) -> Option<Purl> {
        for parser in &self.parsers {
            if parser.can_parse(url) {
                return parser.get_purl(document, line_position);
            }
        }
        None
    }
}
