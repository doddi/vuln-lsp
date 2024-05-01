use anyhow::anyhow;
use serde::Deserialize;
use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::process::Command;

use crate::lsp::document_store::{Position, Range};
use crate::{lsp::document_store::PurlRange, server::purl::Purl};

#[derive(Debug)]
struct MetadataDependencies {
    dependencies: HashMap<Purl, MetadataDependency>,
}

#[derive(Debug)]
struct MetadataDependency {
    direct_dependency: PurlRange,
    dependencies: Vec<Purl>,
}

#[derive(Debug, Deserialize)]
struct Metadata {
    pub packages: Vec<Package>,
    pub resolve: Resolve,
}

#[derive(Debug, Deserialize)]
struct Node {
    pub id: String,
    pub dependencies: Vec<String>
}

#[derive(Debug, Deserialize)]
struct Package {
    pub name: String,
    pub version: String,
    pub id: String,
    pub dependencies: Vec<Dependency>,
}

impl Into<Purl> for Package {
    fn into(self) -> Purl {
        Purl { package: "cargo".to_string(), group_id: None, artifact_id: self.name, version: self.version, purl_type: None }
    }
}

impl Into<Purl> for &Package {
    fn into(self) -> Purl {
        Purl { package: "cargo".to_string(), group_id: None, artifact_id: self.name.clone(), version: self.version.clone(), purl_type: None }
    }
}

#[derive(Debug, Deserialize)]
struct Resolve {
    pub nodes: Vec<Node>,
    pub root: String,
}

#[derive(Debug, Deserialize)]
struct Dependency {
    name: String,
}

fn metadata_command(purls: Vec<PurlRange>) -> anyhow::Result<MetadataDependencies> {
    let output = Command::new("cargo")
        .args(["metadata"])
        .output()
        .expect("failed to execute metadata command");

    // TODO: Check for error before continuing

    let display = String::from_utf8(output.stdout).unwrap();
    match metadata_parse(display.as_str()) {
        Ok(metadata) => metadata_process(purls, metadata),
        Err(e) => Err(anyhow!("Parse error {e}"))
    }
}

fn metadata_parse(data: &str) -> anyhow::Result<Metadata> {
    let result = serde_json::from_str(data);

    match result {
        Ok(data) => Ok(data),
        Err(e) => Err(anyhow!("Unable to parse metadata: {}", e)),
    }
}

fn metadata_process(
    purls: Vec<PurlRange>,
    metadata: Metadata,
) -> anyhow::Result<MetadataDependencies> {
    let root_id = metadata.resolve.root;

    let node_map: BTreeMap<String, Node> = metadata.resolve.nodes.into_iter().map(|node| (node.id.clone(), node)).collect();

    let root_node = node_map.get(&root_id).expect("should have a root node");

    // Iterate over all the root dependencies and renetrant collate all the child dependencies
    let root_dependencies = &root_node.dependencies;

    let mut dep_collection: HashMap<String, Vec<String>> = HashMap::new();

    for dep in root_dependencies {
        // let d = dep_collection.get(dep).expect("Should always be able to get root component");
        let mut d = Vec::new();
        add_dependencies(&node_map, &mut d, dep);
        dep_collection.insert(dep.clone(), d);
    }

    // At this point we have all the projects direct dependencies collated list of child dependecies
    let package_map: BTreeMap<String, Package> = metadata.packages.into_iter().map(|package| (package.id.clone(), package)).collect();

    let mut dependencies = HashMap::new();
    dep_collection.iter().for_each(|dep| {
        let package_purl: Purl = package_map.get(dep.0)
            .expect("unable to find package from id").into();

        // Does the purl exist in the already parsed dependecies provided?
        let exists = purls.iter().find(|item| item.purl.eq(&package_purl));

        match exists {
            Some(purl_range) => {
                let children: Vec<Purl> = dep.1.iter().map(|ele| {
                    package_map.get(ele).expect("child not found").into()
                }).collect();

                let meta = MetadataDependency {
                    direct_dependency: purl_range.clone(),
                    dependencies: children,
                };

                dependencies.insert(package_purl, meta);
            },
            None => println!("Provided PurlRange missing"),
        }
    });

    let result = MetadataDependencies {
        dependencies,
    };

    Ok(result)
}

fn add_dependencies(node_map: &BTreeMap<String, Node>, collection: &mut Vec<String>, dep: &String) {
    let current_node = node_map.get(dep).expect("expected");
    for dep in &current_node.dependencies {
        collection.push(dep.into());
        add_dependencies(node_map, collection, &dep);
    }
}

#[cfg(test)]
mod test {
    use crate::lsp::document_store::{Position, Range};

    use super::*;

    #[test]
    fn can_spawn_metadata_command() {
        // let output = metadata_command();

        // assert_eq!(output.len(), 0)
    }

    #[test]
    fn can_parse_metadata() {
        let data = include_str!("../../../resources/cargo/output.json");
        let metadata = metadata_parse(data).unwrap();

        assert_eq!(metadata.packages.len(), 196)
    }

    #[test]
    fn can_process_metadata() {
        let purls: Vec<PurlRange> = vec![
            PurlRange {
                purl: Purl {
                    package: "cargo".to_string(),
                    group_id: Option::None,
                    artifact_id: "anyhow".to_string(),
                    version: "0.1.74".to_string(),
                    purl_type: Option::None,
                },
                range: Range {
                    start: Position { row: 0, col: 0 },
                    end: Position { row: 1, col: 10 },
                },
            },
            PurlRange {
                purl: Purl {
                    package: "cargo".to_string(),
                    group_id: Option::None,
                    artifact_id: "clap".to_string(),
                    version: "4.4.11".to_string(),
                    purl_type: Option::None,
                },
                range: Range {
                    start: Position { row: 0, col: 0 },
                    end: Position { row: 1, col: 10 },
                },
            },
            PurlRange {
                purl: Purl {
                    package: "cargo".to_string(),
                    group_id: Option::None,
                    artifact_id: "reqwest".to_string(),
                    version: "0.11.22".to_string(),
                    purl_type: Option::None,
                },
                range: Range {
                    start: Position { row: 0, col: 0 },
                    end: Position { row: 1, col: 10 },
                },
            },
        ];
        let data = include_str!("../../../resources/cargo/output.json");
        let metadata = metadata_parse(data).unwrap();

        let dependencies = metadata_process(purls, metadata).unwrap();
    }
}
