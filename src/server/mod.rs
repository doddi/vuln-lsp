use async_trait::async_trait;

use self::{dummy::Dummy, purl::Purl};

pub(crate) mod dummy;
pub(crate) mod ossindex;
pub mod purl;

pub enum VulnerableServerType {
    Dummy,
    OssIndex,
}

#[derive(Debug, Clone)]
pub(crate) struct VulnerabilityInformationResponse {
    pub purl: Purl,
    pub versions: Vec<VulnerabilityVersionInfo>,
}

#[derive(Debug, Clone)]
pub(crate) struct VulnerabilityVersionInfo {
    pub version: String,
    pub severity: Severity,
    pub information: Information,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Severity {
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Clone)]
pub(crate) struct Information {
    pub summary: String,
    pub detail: String,
}

#[async_trait]
pub(crate) trait VulnerabilityServer: Send + Sync {
    async fn get_component_information(
        &self,
        purls: Vec<Purl>,
    ) -> anyhow::Result<Vec<VulnerabilityInformationResponse>>;
}

pub(crate) async fn get_vulnerability_information_for_purls(
    purls: Vec<Purl>,
) -> anyhow::Result<Vec<VulnerabilityInformationResponse>> {
    let server: Box<dyn VulnerabilityServer> = Box::new(Dummy {});

    server.get_component_information(purls).await
}
