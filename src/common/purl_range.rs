use super::{purl::Purl, range::Range};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PurlRange {
    pub purl: Purl,
    pub range: Range,
}

impl PurlRange {
    pub fn new(purl: Purl, range: Range) -> Self {
        PurlRange { purl, range }
    }
}
