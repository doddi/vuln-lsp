use std::any::Any;
use std::fmt::{Display, Formatter};

use serde::de::Visitor;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::pom::parser::Dependency;

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Purl {
    pub package: String,
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub purl_type: Option<String>,
}

impl Display for Purl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let _ = write!(
            f,
            "pkg:{}/{}/{}@{}",
            self.package, self.group_id, self.artifact_id, self.version
        );

        match &self.purl_type {
            Some(purl_type) => {
                let _ = write!(f, "?type={purl_type}");
                Ok(())
            }
            None => Ok(()),
        }
    }
}

impl Serialize for Purl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Purl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(PurlVisitor)
    }
}

struct PurlVisitor;
impl Visitor<'_> for PurlVisitor {
    type Value = Purl;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str(format!("a valid purl: {:?}", self.type_id()).as_str())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let parts: Vec<_> = value.split('/').collect();

        let (package_type, group_id, artifact_and_version) = match parts.len() {
            0..=1 => return Err(E::custom("invalid purl")),
            2 => {
                let package = parts[0];
                let package_type = match extract_package_type(package) {
                    Ok(value) => value,
                    Err(value) => return value,
                };

                let artifact_id = parts[1];
                (package_type, "", artifact_id)
            }
            3 => {
                let package = parts[0];
                let package_type = match extract_package_type(package) {
                    Ok(value) => value,
                    Err(value) => return value,
                };

                let group_id = parts[1];
                let artifact_id = parts[2];
                (package_type, group_id, artifact_id)
            }
            _ => return Err(E::custom("invalid purl")),
        };

        let artifact_and_version: Vec<_> = artifact_and_version.split('@').collect();
        if artifact_and_version.len() != 2 {
            return Err(E::custom("invalid purl, version not found"));
        }

        let artifact_id = artifact_and_version[0].to_string();
        let version_split: Vec<_> = artifact_and_version[1].split('?').collect();

        let (version, purl_type) = match version_split.len() {
            0 => {
                warn!("No version available");
                ("", None)
            }
            1 => (version_split[0], None),
            _ => (version_split[0], find_package_type(version_split[1])),
        };

        Ok(Purl {
            package: package_type.to_string(),
            group_id: group_id.to_string(),
            artifact_id,
            version: version.to_string(),
            purl_type,
        })
    }
}

fn find_package_type(qualifiers: &str) -> Option<String> {
    let split: Vec<_> = qualifiers.split('&').collect();

    split
        .into_iter()
        .find(|qualifier| qualifier.starts_with("type="))
        .map(|type_qualifier| type_qualifier.replace("type=", ""))
}

fn extract_package_type<E>(package: &str) -> Result<String, Result<Purl, E>>
where
    E: serde::de::Error,
{
    if !package.starts_with("pkg:") {
        return Err(Err(E::custom("invalid pkg prefix")));
    }
    let package_type = package.replace("pkg:", "");
    Ok(package_type)
}

impl From<Purl> for Dependency {
    fn from(value: Purl) -> Self {
        Dependency {
            group_id: value.group_id,
            artifact_id: value.artifact_id,
            version: Some(value.version),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PurlRange {
    pub purl: Purl,
    pub range: Range,
}

impl PurlRange {
    pub fn new(purl: Purl, range: Range) -> Self {
        PurlRange { purl, range }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Range {
    pub start: Position,
    pub end: Position,
}

impl Range {
    pub fn new(start: Position, end: Position) -> Self {
        Range { start, end }
    }
    pub fn contains_position(&self, line_number: usize) -> bool {
        line_number >= self.start.row && line_number <= self.end.row
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Position {
    pub row: usize,
    pub col: usize,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_deserialize() {
        let purl = "\"pkg:maven/org.apache.commons/commons-lang3@3.9?type=jar\"";
        let purl: Purl = serde_json::from_str(purl).unwrap();

        assert_eq!(purl.package, "maven");
        assert_eq!(purl.group_id, "org.apache.commons");
        assert_eq!(purl.artifact_id, "commons-lang3");
        assert_eq!(purl.version, "3.9");
    }

    #[test]
    fn can_deserialize_npm() {
        let purl = "\"pkg:npm/foobar@12.3.1\"";
        let purl: Purl = serde_json::from_str(purl).unwrap();

        assert_eq!(purl.package, "npm");
        assert_eq!(purl.group_id, "");
        assert_eq!(purl.artifact_id, "foobar");
        assert_eq!(purl.version, "12.3.1");
    }

    #[test]
    fn can_deserialize_struts() {
        let purl: Purl =
            serde_json::from_str("\"pkg:maven/org.apache.struts/struts-core@1.3.10\"").unwrap();

        assert_eq!(purl.package, "maven");
        assert_eq!(purl.group_id, "org.apache.struts");
        assert_eq!(purl.artifact_id, "struts-core");
        assert_eq!(purl.version, "1.3.10");
    }
}
