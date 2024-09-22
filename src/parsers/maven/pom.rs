use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{trace, warn};

use crate::common::{
    purl::Purl,
    range::{Position, Range},
};

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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub(super) struct Dependency {
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

pub(super) type PomMetadataDependencies = HashMap<Dependency, Range>;

// It is not possible to simply parse the entire file using serde because
// it could be that the content is not valid xml.
// So the approach I have taken here is to iterate over it line by line
pub fn determine_dependencies_with_range(document: &str) -> PomMetadataDependencies {
    let lines = document.lines().collect::<Vec<&str>>();

    let mut dep_start = None;
    let mut dep_end = None;
    let mut dependencies = HashMap::new();
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
            if let Ok((depenency, range)) = extract_dependency(&lines, start, end) {
                dependencies.insert(depenency, range);
            }
            dep_start = None;
            dep_end = None;
        }
    }
    dependencies
}

fn extract_dependency(
    lines_for_extraction: &[&str],
    start: &Position,
    end: &Position,
) -> Result<(Dependency, Range), String> {
    trace!("Extracting dependency information");
    let dependency_scope = &lines_for_extraction[start.row..=end.row];
    match serde_xml_rs::from_str::<Dependency>(dependency_scope.concat().as_str()) {
        Ok(dep) => {
            trace!("Found dependency: {:?}", dep);
            let range = Range::new(start.clone(), end.clone());
            Ok((dep, range))
        }
        Err(err) => {
            warn!("Failed to parse dependency: {}", err);
            Err(err.to_string())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_extract_dependency() {
        let content = r#"
            <dependency>
                <groupId>junit</groupId>
                <artifactId>junit</artifactId>
                <version>4.8.2</version>
                <scope>test</scope>
            </dependency>
            "#;
        let lines = content.lines().collect::<Vec<&str>>();
        let start = Position { row: 1, col: 0 };
        let end = Position { row: 6, col: 0 };

        let response = extract_dependency(&lines, &start, &end);

        assert!(response.is_ok());
        let actual = response.unwrap();
        assert_eq!(
            actual.0,
            Dependency {
                group_id: "junit".to_string(),
                artifact_id: "junit".to_string(),
                version: Some("4.8.2".to_string()),
            }
        );
        assert_eq!(actual.1.start.row, 1);
        assert_eq!(actual.1.start.col, 0);
        assert_eq!(actual.1.end.row, 6);
        assert_eq!(actual.1.end.col, 0);
    }

    #[test]
    fn test_extract_dependencies() {
        let doc = include_str!("../../../resources/maven/pom.xml");

        let response = determine_dependencies_with_range(doc);
        assert!(!response.is_empty());
        assert_eq!(response.len(), 3);

        let mut test_map: HashMap<String, Range> = HashMap::new();

        response.into_iter().for_each(|(key, value)| {
            test_map.insert(key.artifact_id, value);
        });

        let mut actual = test_map.get("selenium-java").unwrap();
        assert_eq!(actual.start.row, 16);
        assert_eq!(actual.end.row, 20);
        actual = test_map.get("opensaml").unwrap();
        assert_eq!(actual.start.row, 21);
        assert_eq!(actual.end.row, 25);
        actual = test_map.get("struts-core").unwrap();
        assert_eq!(actual.start.row, 26);
        assert_eq!(actual.end.row, 30);
    }

    #[test]
    fn test_extract_dependencies_without_version() {
        let doc = include_str!("../../../resources/maven/pom_without_version.xml");

        let response = determine_dependencies_with_range(doc);
        assert!(!response.is_empty());
        assert_eq!(response.len(), 3);

        let mut test_map: HashMap<String, Range> = HashMap::new();

        response.into_iter().for_each(|(key, value)| {
            test_map.insert(key.artifact_id, value);
        });

        let mut actual = test_map.get("selenium-java").unwrap();
        assert_eq!(actual.start.row, 16);
        assert_eq!(actual.end.row, 19);
        actual = test_map.get("opensaml").unwrap();
        assert_eq!(actual.start.row, 20);
        assert_eq!(actual.end.row, 24);
        actual = test_map.get("struts-core").unwrap();
        assert_eq!(actual.start.row, 25);
        assert_eq!(actual.end.row, 29);
    }
}
