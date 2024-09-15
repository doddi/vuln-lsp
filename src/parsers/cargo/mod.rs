mod build_command;
mod toml;

use crate::common::MetadataDependencies;
use build_command::build_command;
use toml::parse_cargo_toml;
use tracing::{debug, trace};

use super::{ParseContent, Parser};

pub(super) struct Cargo {
    direct_only: bool,
}

impl Cargo {
    pub(crate) fn new(direct_only: bool) -> Self {
        Self { direct_only }
    }
}

impl Parser for Cargo {
    fn can_parse(&self, url: &reqwest::Url) -> bool {
        url.path().ends_with("Cargo.toml")
    }

    fn parse(&self, document: &str) -> anyhow::Result<ParseContent> {
        debug!("Parsing Cargo.toml");

        let ranges: MetadataDependencies = parse_cargo_toml(document)?;
        // TODO: Add parsing transitives - cant at the moment because it creates
        // too many depenencies for large projects so would need to look at
        // batching the calls to the backend.
        let transitives;
        if self.direct_only {
            trace!("Only considering the direct dependencies");
            transitives = ranges
                .clone()
                .keys()
                .map(|purl| (purl.clone(), vec![purl.clone()]))
                .collect();
        } else {
            transitives = build_command()?;
        }

        Ok(ParseContent {
            ranges,
            transitives,
        })
    }
}
