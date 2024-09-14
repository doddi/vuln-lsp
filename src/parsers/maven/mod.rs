mod pom;

use crate::common::{BuildDependencies, MetadataDependencies};

use super::{ParseContent, Parser};

pub(crate) struct Maven {}

impl Maven {
    pub fn new() -> Self {
        Self {}
    }
}

impl Parser for Maven {
    fn can_parse(&self, url: &reqwest::Url) -> bool {
        url.path().ends_with("pom.xml")
    }

    fn parse(&self, document: &str) -> anyhow::Result<ParseContent> {
        let purls: MetadataDependencies = pom::determine_dependencies_with_range(document);

        // TODO: Use a maven command to determine all dependencies including transitives
        let transitives: BuildDependencies = purls
            .clone()
            .keys()
            .map(|purl| (purl.clone(), vec![purl.clone()]))
            .collect();

        let content = ParseContent {
            ranges: purls,
            transitives,
        };
        Ok(content)
    }
}
