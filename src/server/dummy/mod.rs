use async_trait::async_trait;

use super::{purl::Purl, Information, Severity, VulnerabilityServer, VulnerabilityVersionInfo};

pub struct Dummy;

impl Dummy {
    // async fn get_version_information_for_purl(
    //     &self,
    //     purl: &Purl,
    // ) -> VulnerabilityInformationResponse {
    //     // TODO Fetch from the real endpoint
    //     VulnerabilityInformationResponse {
    //         purl: purl.clone(),
    //         versions: vec![
    //             VulnerabilityVersionInfo {
    //                 version: "1.0.0".to_string(),
    //                 severity: Severity::High,
    //                 information: Information {
    //                     summary: "Summary 1".to_string(),
    //                     detail: "Detail 1".to_string(),
    //                 },
    //             },
    //             VulnerabilityVersionInfo {
    //                 version: "2.0.0".to_string(),
    //                 severity: Severity::None,
    //                 information: Information {
    //                     summary: "Summary 2".to_string(),
    //                     detail: "Detail 2".to_string(),
    //                 },
    //             },
    //         ],
    //     }
    // }
}

#[async_trait]
impl VulnerabilityServer for Dummy {
    async fn get_versions_for_purl(
        &self,
        purl: Purl,
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>> {
        let versions = vec![
            VulnerabilityVersionInfo {
                purl: purl.clone(),
                information: Information {
                    summary: "Summary 1".to_string(),
                    severity: Severity::High,
                    detail: "Detail 1".to_string(),
                },
            },
            VulnerabilityVersionInfo {
                purl: purl.clone(),
                information: Information {
                    summary: "Summary 2".to_string(),
                    severity: Severity::None,
                    detail: "Detail 2".to_string(),
                },
            },
        ];
        anyhow::Ok(versions)
    }

    async fn get_component_information(
        &self,
        purls: Vec<Purl>,
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>> {
        let response = purls
            .iter()
            .enumerate()
            .map(|(index, purl)| VulnerabilityVersionInfo {
                purl: purl.clone(),
                information: Information {
                    summary: format!("Summary {index}").to_string(),
                    severity: Severity::High,
                    detail: format!("Detail {index}").to_string(),
                },
            })
            .collect();
        anyhow::Ok(response)
    }

    // async fn get_component_information(
    //     &self,
    //     purls: Vec<Purl>,
    // ) -> anyhow::Result<Vec<VulnerabilityInformationResponse>> {
    //     let purls = futures::future::join_all(
    //         purls
    //             .iter()
    //             .map(|purl| self.get_version_information_for_purl(purl)),
    //     )
    //     .await;
    //     anyhow::Ok(purls)
    // }
}
