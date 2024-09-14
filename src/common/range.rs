#[derive(Clone, Debug, PartialEq, Default, Eq, Hash)]
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

#[derive(Clone, Debug, PartialEq, Default, Eq, Hash)]
pub(crate) struct Position {
    pub row: usize,
    pub col: usize,
}
