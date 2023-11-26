use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::Purl;

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

#[derive(Debug, PartialEq)]
struct DependencyRange {
    pub start: usize,
    pub end: Option<usize>,
}

// fn find_dependency_on_line(
//     dependencies: &HashMap<DependencyRange, Dependency>,
//     line: usize,
// ) -> Option<&Dependency> {
//     dependencies
//         .iter()
//         .find(|(range, _)| line >= range.start && line <= range.end)
//         .map(|(_, dependency)| dependency)
// }

fn to_project(content: &str) -> anyhow::Result<Project> {
    Ok(serde_xml_rs::from_str::<Project>(content)?)
}

pub fn is_editing_version(content: &str, line: usize) -> bool {
    content
        .lines()
        .nth(line)
        .unwrap_or_default()
        .contains("<version>")
}

pub fn get_purl(document: &String, line_position: usize) -> Option<Purl> {
    todo!()
}

// fn to_pom(content: &str) -> anyhow::Result<HashMap<Dependency, DependencyRange>> {}

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
        let project = to_project(content).unwrap();

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
}
