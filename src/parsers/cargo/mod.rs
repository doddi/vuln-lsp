mod build_command;
mod toml;

use crate::common::{BuildDependencies, MetadataDependencies};
use build_command::build_command;
use toml::parse_cargo_toml;
use tracing::debug;

use super::{ParseContent, Parser};

pub(super) struct Cargo;

impl Cargo {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

impl Parser for Cargo {
    fn can_parse(&self, url: &reqwest::Url) -> bool {
        url.path().ends_with("Cargo.toml")
    }

    fn parse(&self, document: &str) -> anyhow::Result<ParseContent> {
        debug!("Parsing Cargo.toml");

        let parsed: MetadataDependencies = parse_cargo_toml(document)?;
        // TODO: Add parsing transitives
        // let transitives: BuildDependencies = build_command()?;
        let transitives: BuildDependencies = parsed
            .clone()
            .keys()
            .map(|purl| (purl.clone(), vec![purl.clone()]))
            .collect();

        Ok(ParseContent {
            ranges: parsed,
            transitives,
        })
    }
}
