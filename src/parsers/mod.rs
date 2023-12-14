mod pom;
use reqwest::Url;

use crate::{
    server::purl::{Purl, PurlRange},
    VulnLspError,
};
use anyhow::anyhow;

trait Parser: Send + Sync {
    fn can_parser(&self, url: &Url) -> bool;
    fn parse(&self, document: &str) -> Vec<PurlRange>;

    fn is_editing_version(&self, document: &str, line_position: usize) -> bool;
    fn get_purl(&self, document: &str, line_position: usize) -> Option<Purl>;
}

pub struct ParserManager {
    parsers: Vec<Box<dyn Parser>>,
}

fn create_pom_parser() -> Box<dyn Parser> {
    Box::new(pom::parser::PomParser {})
}

impl ParserManager {
    pub fn new() -> Self {
        let parsers = vec![create_pom_parser()];

        Self { parsers }
    }

    pub fn parse(&self, url: &Url, document: &str) -> anyhow::Result<Vec<PurlRange>> {
        for parser in &self.parsers {
            if parser.can_parser(url) {
                return anyhow::Ok(parser.parse(document));
            }
        }
        Err(anyhow!(VulnLspError::ParserNotFoundError(url.clone())))
    }

    pub fn is_editing_version(&self, url: &Url, document: &str, line_position: usize) -> bool {
        for parser in &self.parsers {
            if parser.can_parser(url) {
                return parser.is_editing_version(document, line_position);
            }
        }
        false
    }

    pub fn get_purl(&self, url: &Url, document: &str, line_position: usize) -> Option<Purl> {
        for parser in &self.parsers {
            if parser.can_parser(url) {
                return parser.get_purl(document, line_position);
            }
        }
        None
    }
}
