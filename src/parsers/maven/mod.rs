mod dep_tree;
mod pom;

use dep_tree::build_dependency_list_from_command;
use pom::{Dependency, PomMetadataDependencies};
use tracing::trace;

use crate::common::{purl::Purl, range::Range, BuildDependencies, MetadataDependencies};

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
        let metadata_dependencies = pom::determine_dependencies_with_range(document);

        let transitives = if !self.include_transitives {
            trace!("Only considering the direct dependencies");
            metadata_dependencies
                .clone()
                .keys()
                .map(|dependency| {
                    let purl: Purl = dependency.clone().into();
                    (purl.clone(), vec![purl])
                })
                .collect()
        } else {
            build_dependency_list_from_command()?
        };

        let ranges = compute_metadata_dependencies_into_purls(metadata_dependencies, &transitives);

        let content = ParseContent {
            ranges,
            transitives,
        };
        Ok(content)
    }
}

fn compute_metadata_dependencies_into_purls(
    metadata_dependencies: PomMetadataDependencies,
    transitives: &BuildDependencies,
) -> MetadataDependencies {
    metadata_dependencies
        .iter()
        .filter_map(|metadata_dependency| determine_purl(metadata_dependency, transitives))
        .collect()
}

fn determine_purl(
    metadata_dependency: (&Dependency, &Range),
    transitives: &BuildDependencies,
) -> Option<(Purl, Range)> {
    let mut build_direct_dependencies = transitives.keys();
    match build_direct_dependencies.find(|build_purl| {
        build_purl.group_id.is_some()
            && build_purl.group_id.clone().unwrap() == metadata_dependency.0.group_id
            && build_purl.artifact_id == metadata_dependency.0.artifact_id
    }) {
        Some(purl) => Some((purl.clone(), metadata_dependency.1.clone())),
        None => None,
    }
}
