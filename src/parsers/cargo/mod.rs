mod build_command;
mod toml;

use crate::common::MetadataDependencies;
use build_command::build_command;
use toml::parse_cargo_toml;
use tracing::{debug, trace};

use super::{ParseContent, Parser};

pub(super) struct Cargo {
    include_transitives: bool,
}

impl Cargo {
    pub(crate) fn new(include_transitives: bool) -> Self {
        Self {
            include_transitives,
        }
    }
}

impl Parser for Cargo {
    fn can_parse(&self, url: &reqwest::Url) -> bool {
        url.path().ends_with("Cargo.toml")
    }

    fn parse(&self, document: &str) -> anyhow::Result<ParseContent> {
        debug!("Parsing Cargo.toml");

        let ranges: MetadataDependencies = parse_cargo_toml(document)?;
        let transitives = if !self.include_transitives {
            trace!("Only considering the direct dependencies");
            ranges
                .clone()
                .keys()
                .map(|purl| (purl.clone(), vec![purl.clone()]))
                .collect()
        } else {
            build_command()?
        };

        Ok(ParseContent {
            ranges,
            transitives,
        })
    }
}
