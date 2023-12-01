use async_trait::async_trait;

use self::purl::Purl;

pub(crate) mod dummy;
pub(crate) mod ossindex;
pub mod purl;

pub enum VulnerableServerType {
    Dummy,
    OssIndex,
}

#[derive(Debug, Clone)]
pub(crate) struct VulnerabilityVersionInfo {
    pub purl: Purl,
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
    pub severity: Severity,
    pub summary: String,
    pub detail: String,
}

#[async_trait]
pub(crate) trait VulnerabilityServer: Send + Sync {
    async fn get_versions_for_purl(
        &self,
        purl: Purl,
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>>;

    async fn get_component_information(
        &self,
        purls: Vec<Purl>,
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>>;
}

// pub(crate) async fn get_vulnerability_information_for_purls(
//     purls: Vec<Purl>,
// ) -> anyhow::Result<Vec<VulnerabilityInformationResponse>> {
//     let server: Box<dyn VulnerabilityServer> = Box::new(Dummy {});
//
//     server.get_component_information(purls).await
// }
