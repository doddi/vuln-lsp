mod pom;

use crate::common::{BuildDependencies, MetadataDependencies};

use super::{ParseContent, Parser};

pub(crate) struct Maven {
    direct_only: bool,
}

impl Maven {
    pub fn new(direct_only: bool) -> Self {
        Self { direct_only }
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
