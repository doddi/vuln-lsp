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

impl From<Dependency> for Purl {
    fn from(value: Dependency) -> Self {
        Purl {
            group_id: value.group_id,
            artifact_id: value.artifact_id,
            version: value.version.unwrap(),
        }
    }
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

// fn to_pom(content: &str) -> anyhow::Result<HashMap<Dependency, DependencyRange>> {
//     let lines = content.lines();
//
//     Ok(dependencies)
// }

pub fn is_editing_version(document: &str, line_position: usize) -> bool {
    let lines = document.lines().collect::<Vec<&str>>();
    let line = lines.get(line_position).unwrap();
    line.contains("<version>") && line.contains("</version>")
}

pub fn get_purl(document: &str, line_position: usize) -> Option<Purl> {
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

    let dependency_scope = lines
        .into_iter()
        .skip(dep_start)
        .take(dep_end - dep_start + 1)
        .collect::<Vec<&str>>()
        .join("\n");

    match serde_xml_rs::from_str::<Dependency>(dependency_scope.as_str()) {
        Ok(dep) => Some(dep.into()),
        Err(err) => {
            eprintln!("{}", err);
            None
        }
    }
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
        assert_eq!(purl.group_id, "junit");
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
        assert_eq!(purl.group_id, "com.foo");
        assert_eq!(purl.artifact_id, "bar");
        assert_eq!(purl.version, "1.0.0");
    }
}
