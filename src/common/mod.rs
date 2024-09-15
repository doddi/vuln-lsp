use std::collections::HashMap;

use purl::Purl;
use range::Range;

pub(crate) mod document_store;
pub(crate) mod errors;
pub(crate) mod purl;
pub(crate) mod purl_range;
pub(crate) mod range;

pub type MetadataDependencies = HashMap<Purl, Range>;
pub type BuildDependencies = HashMap<Purl, Vec<Purl>>;
