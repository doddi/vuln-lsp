use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::pom::parser::Dependency;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Purl {
    pub package: String,
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
}

impl Display for Purl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pkg:{}/{}/{}@{}",
            self.package, self.group_id, self.artifact_id, self.version
        )
    }
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

impl Position {
    pub fn new(row: usize, col: usize) -> Self {
        Position { row, col }
    }
}
