use async_trait::async_trait;

use self::purl::Purl;

pub(crate) mod cacher;
pub(crate) mod dummy;
pub(crate) mod ossindex;
pub mod purl;
pub(crate) mod sonatype;

#[derive(Debug, Clone)]
pub enum VulnerableServerType {
    Dummy,
    OssIndex,
    Sonatype { base_url: String },
}

#[derive(Debug, Clone)]
pub(crate) struct VulnerabilityVersionInfo {
    pub purl: Purl,
    pub vulnerabilities: Vec<Information>,
}

impl VulnerabilityVersionInfo {
    pub fn find_highest_severity_vulnerability<'a>(
        &self,
        vulnerabilities: &'a [Information],
    ) -> Option<&'a Information> {
        vulnerabilities
            .iter()
            .max_by(|a, b| a.severity.cmp(&b.severity))
    }
}

#[derive(Debug, Clone, Ord, PartialEq, PartialOrd, Eq)]
pub(crate) enum Severity {
    Critical,
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Clone)]
pub(crate) struct Information {
    pub severity: Severity,
    pub summary: String,
    pub detail: String,
    pub license: Vec<License>,
}

#[derive(Debug, Clone)]
pub(crate) struct License {
    pub title: String,
    pub description: String,
}

#[async_trait]
pub(crate) trait VulnerabilityServer: Send + Sync {
    async fn get_versions_for_purl(&self, purl: Purl) -> anyhow::Result<Vec<Purl>>;

    async fn get_component_information(
        &self,
        purls: Vec<Purl>,
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>>;
}
