use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{trace, warn};

use crate::common::{
    purl::Purl,
    purl_range::PurlRange,
    range::{Position, Range},
    MetadataDependencies,
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

// It is not possible to simply parse the entire file using serde because
// it could be that the content is not valid xml.
// So the approach I have taken here is to iterate over it line by line
pub fn determine_dependencies_with_range(document: &str) -> MetadataDependencies {
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
            if let Ok(depenency) = extract_dependency(&lines, start, end) {
                dependencies.insert(depenency.purl, depenency.range);
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
) -> Result<PurlRange, String> {
    trace!("Extracting dependency information");
    let dependency_scope = &lines_for_extraction[start.row..=end.row];
    match serde_xml_rs::from_str::<Dependency>(dependency_scope.concat().as_str()) {
        Ok(dep) => {
            trace!("Found dependency: {:?}", dep);
            let range = Range::new(start.clone(), end.clone());
            Ok(PurlRange::new(dep.into(), range))
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
            actual.purl,
            Purl {
                package: "maven".to_string(),
                group_id: Some("junit".to_string()),
                artifact_id: "junit".to_string(),
                version: "4.8.2".to_string(),
                purl_type: Some("jar".to_string()),
            }
        );
        assert_eq!(actual.range.start.row, 1);
        assert_eq!(actual.range.start.col, 0);
        assert_eq!(actual.range.end.row, 6);
        assert_eq!(actual.range.end.col, 0);
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
}
