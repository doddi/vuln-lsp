use async_trait::async_trait;

use super::{
    purl::Purl, Information, Severity, VulnerabilityInformationResponse, VulnerabilityServer,
    VulnerabilityVersionInfo,
};

pub struct Dummy;

impl Dummy {
    async fn get_version_information_for_purl(
        &self,
        purl: &Purl,
    ) -> VulnerabilityInformationResponse {
        // TODO Fetch from the real endpoint
        VulnerabilityInformationResponse {
            purl: purl.clone(),
            versions: vec![
                VulnerabilityVersionInfo {
                    version: "1.0.0".to_string(),
                    severity: Severity::High,
                    information: Information {
                        summary: "Summary 1".to_string(),
                        detail: "Detail 1".to_string(),
                    },
                },
                VulnerabilityVersionInfo {
                    version: "2.0.0".to_string(),
                    severity: Severity::None,
                    information: Information {
                        summary: "Summary 2".to_string(),
                        detail: "Detail 2".to_string(),
                    },
                },
            ],
        }
    }
}

#[async_trait]
impl VulnerabilityServer for Dummy {
    async fn get_version_information_for_purls(
        &self,
        purls: Vec<Purl>,
    ) -> Vec<VulnerabilityInformationResponse> {
        futures::future::join_all(
            purls
                .iter()
                .map(|purl| self.get_version_information_for_purl(purl)),
        )
        .await
    }
}
