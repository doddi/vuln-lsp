use pom::parser::Dependency;
use serde::{Deserialize, Serialize};

pub mod lsp;
pub mod pom;
pub mod vulnerability_server;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Purl {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
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

#[derive(Debug, PartialEq)]
pub struct RangedPurl {
    pub purl: Purl,
    pub range: Range,
}

#[derive(Debug, PartialEq)]
pub struct Range {
    pub start: usize,
    pub end: usize,
}

impl Range {
    pub fn new(start: usize, end: usize) -> Self {
        Range { start, end }
    }
}

impl RangedPurl {
    pub fn new(purl: Purl, start: usize, end: usize) -> Self {
        RangedPurl {
            purl,
            range: Range::new(start, end),
        }
    }
}
