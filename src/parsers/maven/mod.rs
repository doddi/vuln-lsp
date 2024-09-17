mod dep_tree;
mod pom;

use dep_tree::build_dependency_list_from_command;
use tracing::trace;

use crate::common::MetadataDependencies;

use super::{ParseContent, Parser};

pub(crate) struct Maven {
    include_transitives: bool,
}

impl Maven {
    pub fn new(include_transitives: bool) -> Self {
        Self {
            include_transitives,
        }
    }
}

impl Parser for Maven {
    fn can_parse(&self, url: &reqwest::Url) -> bool {
        url.path().ends_with("pom.xml")
    }

    fn parse(&self, document: &str) -> anyhow::Result<ParseContent> {
        let ranges: MetadataDependencies = pom::determine_dependencies_with_range(document);

        let transitives = if !self.include_transitives {
            trace!("Only considering the direct dependencies");
            ranges
                .clone()
                .keys()
                .map(|purl| (purl.clone(), vec![purl.clone()]))
                .collect()
        } else {
            build_dependency_list_from_command()?
        };

        let content = ParseContent {
            ranges,
            transitives,
        };
        Ok(content)
    }
}
