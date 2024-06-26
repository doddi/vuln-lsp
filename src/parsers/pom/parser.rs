use serde::{de, Deserialize, Serialize};
use tracing::{debug, trace, warn};

use crate::{
    lsp::document_store::{MetadataDependencies, Position, PurlRange, Range},
    parsers::Parser,
    server::purl::Purl,
};

pub(crate) struct PomParser;

impl Parser for PomParser {
    fn parse(&self, document: &str) -> anyhow::Result<MetadataDependencies> {
        trace!("Parsing pom.xml");
        let dependencies = calculate_dependencies_with_range(document);
        trace!("Found dependencies: {:?}", dependencies);
        let mut metadata = MetadataDependencies::new();
        dependencies.into_iter().for_each(|dep| {
            metadata.insert(dep, vec![]);
        });
        Ok(metadata)
    }

    fn can_parse(&self, url: &reqwest::Url) -> bool {
        url.path().ends_with("pom.xml")
    }

    fn is_editing_version(&self, document: &str, line_position: usize) -> bool {
        is_editing_version(document, line_position)
    }

    fn get_purl(&self, document: &str, line_position: usize) -> Option<Purl> {
        get_purl(document, line_position)
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct Project {
    #[serde(rename = "groupId")]
    pub group_id: String,
    #[serde(rename = "artifactId")]
    pub artifact_id: String,
    pub version: String,

    pub name: String,

    pub dependencies: Dependencies,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct Dependencies {
    pub dependency: Vec<Dependency>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
struct Dependency {
    #[serde(rename = "groupId")]
    pub group_id: String,
    #[serde(rename = "artifactId")]
    pub artifact_id: String,
    pub version: Option<String>,
}

impl From<Purl> for Dependency {
    fn from(value: Purl) -> Self {
        Dependency {
            group_id: value.group_id.unwrap(),
            artifact_id: value.artifact_id,
            version: Some(value.version),
        }
    }
}

impl From<Dependency> for Purl {
    fn from(value: Dependency) -> Self {
        Purl {
            package: "maven".to_string(),
            group_id: Some(value.group_id),
            artifact_id: value.artifact_id,
            version: value.version.unwrap(),
            purl_type: Some("jar".to_string()),
        }
    }
}

fn is_editing_version(document: &str, line_position: usize) -> bool {
    let lines = document.lines().collect::<Vec<&str>>();
    let line = lines.get(line_position).unwrap();

    debug!(
        "Checking if line {} contains version: {}",
        line_position, line
    );
    line.contains("<version>") && line.contains("</version>")
}

fn get_purl(document: &str, line_position: usize) -> Option<Purl> {
    let lines = document.lines().collect::<Vec<&str>>();

    let mut dep_start = 0;
    let mut dep_end = 0;
    for (index, line) in lines.iter().enumerate() {
        if line.contains("<dependency>") && index < line_position {
            dep_start = index;
        }
        if line.contains("</dependency>") && index > line_position {
            dep_end = index;
        }
    }

    debug!("Dependency range: {} - {}", dep_start, dep_end);

    let dependency_scope = lines
        .into_iter()
        .skip(dep_start)
        .take(dep_end - dep_start + 1)
        .collect::<Vec<&str>>()
        .join("\n");

    match serde_xml_rs::from_str::<Dependency>(dependency_scope.as_str()) {
        Ok(dep) => Some(dep.into()),
        Err(err) => {
            warn!("Failed to parse dependency: {}", err);
            None
        }
    }
}

fn calculate_dependencies_with_range(document: &str) -> Vec<PurlRange> {
    let lines = document.lines().collect::<Vec<&str>>();

    let mut dep_start = None;
    let mut dep_end = None;
    let mut dependencies = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if let Some(col) = line.find("<dependency>") {
            trace!("Found dependency start at {}", index);
            dep_start = Some(Position { row: index, col });
        } else if let Some(col) = line.find("</dependency>") {
            trace!("Found dependency end at {}", index);
            dep_end = Some(Position {
                row: index,
                col: col + "</dependency>".to_string().len(),
            });
        }

        if let (Some(start), Some(end)) = (&dep_start, &dep_end) {
            trace!("Extracting dependency information");
            // TODO: Bad Bad Bad, need to iterate over a single time
            let lines_for_extraction = document.lines().collect::<Vec<&str>>();
            let dependency_scope = lines_for_extraction
                .into_iter()
                .skip(start.row)
                .take(end.row - start.row + 1)
                .collect::<Vec<&str>>()
                .join("\n");
            match serde_xml_rs::from_str::<Dependency>(dependency_scope.as_str()) {
                Ok(dep) => {
                    trace!("Found dependency: {:?}", dep);
                    let range = Range::new(
                        Position {
                            row: start.row,
                            col: start.col,
                        },
                        Position {
                            row: end.row,
                            col: end.col,
                        },
                    );
                    let purl_range = PurlRange::new(dep.into(), range);
                    dependencies.push(purl_range);
                }
                Err(err) => {
                    warn!("Failed to parse dependency: {}", err);
                }
            }
            dep_start = None;
            dep_end = None;
        }
    }
    dependencies
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn parse_pom_file() {
        let content = r#"
            <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">

                <modelVersion>4.0.0</modelVersion>

                <groupId>com.example</groupId>
                <artifactId>demo</artifactId>
                <version>1.0</version>
                <packaging>jar</packaging>

                <name>Maven Quick Start Archetype</name>
                <url>http://maven.apache.org</url>

                <dependencies>
                    <dependency>
                        <groupId>junit</groupId>
                        <artifactId>junit</artifactId>
                        <version>4.8.2</version>
                        <scope>test</scope>
                    </dependency>
                    <dependency>
                        <groupId>test</groupId>
                        <artifactId>foo</artifactId>
                        <version>1.0.0</version>
                    </dependency>
                </dependencies>

            </project>
            "#;

        let project = serde_xml_rs::from_str::<Project>(content).unwrap();

        assert_eq!(project.group_id, "com.example");
        assert_eq!(project.artifact_id, "demo");
        assert_eq!(project.version, "1.0");
        assert_eq!(project.name, "Maven Quick Start Archetype");

        assert_eq!(project.dependencies.dependency.len(), 2);
        assert_eq!(project.dependencies.dependency[0].group_id, "junit");
        assert_eq!(project.dependencies.dependency[0].artifact_id, "junit");
        assert_eq!(
            project.dependencies.dependency[0].version,
            Some("4.8.2".to_string())
        );

        assert_eq!(project.dependencies.dependency[1].group_id, "test");
        assert_eq!(project.dependencies.dependency[1].artifact_id, "foo");
        assert_eq!(
            project.dependencies.dependency[1].version,
            Some("1.0.0".to_string())
        );
    }

    #[test]
    pub fn get_purl_from_dependency() {
        let content = r#"
            <dependency>
                <groupId>junit</groupId>
                <artifactId>junit</artifactId>
                <version>4.8.2</version>
                <scope>test</scope>
            </dependency>
            "#;
        let purl = get_purl(content, 3).unwrap();
        assert_eq!(purl.group_id.unwrap(), "junit");
        assert_eq!(purl.artifact_id, "junit");
        assert_eq!(purl.version, "4.8.2");
    }

    #[test]
    pub fn get_purl_from_dependencies() {
        let content = r#"
        <dependencies>
            <dependency>
                <groupId>junit</groupId>
                <artifactId>junit</artifactId>
                <version>4.8.2</version>
                <scope>test</scope>
            </dependency>
            <dependency>
                <groupId>com.foo</groupId>
                <artifactId>bar</artifactId>
                <version>1.0.0</version>
                <scope>test</scope>
            </dependency>
        <dependencies>
        "#;
        let purl = get_purl(content, 12).unwrap();
        assert_eq!(purl.group_id.unwrap(), "com.foo");
        assert_eq!(purl.artifact_id, "bar");
        assert_eq!(purl.version, "1.0.0");
    }
}
