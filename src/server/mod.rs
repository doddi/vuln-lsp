use async_trait::async_trait;

use self::{dummy::Dummy, purl::Purl};

mod dummy;
mod ossindex;
pub mod purl;

#[derive(Debug, Clone)]
pub struct VulnerabilityInformationResponse {
    pub purl: Purl,
    pub versions: Vec<VulnerabilityVersionInfo>,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityVersionInfo {
    pub version: String,
    pub severity: Severity,
    pub information: Information,
}

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Clone)]
pub struct Information {
    pub summary: String,
    pub detail: String,
}

#[async_trait]
pub trait VulnerabilityServer: Send + Sync {
    async fn get_version_information_for_purls(
        &self,
        purls: Vec<Purl>,
    ) -> Vec<VulnerabilityInformationResponse>;
}

pub async fn get_vulnerability_information_for_purls(
    purls: Vec<Purl>,
) -> Vec<VulnerabilityInformationResponse> {
    let server: Box<dyn VulnerabilityServer> = Box::new(Dummy {});

    server.get_version_information_for_purls(purls).await
}
