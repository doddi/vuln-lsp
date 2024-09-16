use async_trait::async_trait;
use rand::Rng;

use crate::common::purl::Purl;

use super::{Severity, VulnerabilityInformation, VulnerabilityServer, VulnerabilityVersionInfo};

pub struct Dummy;

impl Dummy {}

#[async_trait]
impl VulnerabilityServer for Dummy {
    async fn get_versions_for_purl(&self, purl: Purl) -> anyhow::Result<Vec<Purl>> {
        let mut other_purl = purl.clone();
        other_purl.version += "1";

        let versions = vec![purl.clone(), other_purl];
        anyhow::Ok(versions)
    }

    async fn get_component_information(
        &self,
        purls: &[Purl],
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>> {
        let response = purls
            .iter()
            .enumerate()
            .map(|(index, purl)| VulnerabilityVersionInfo {
                purl: purl.clone(),
                vulnerabilities: vec![VulnerabilityInformation {
                    summary: format!("Summary {index}").to_string(),
                    severity: random_severity(),
                    detail: format!("Detail {index}").to_string(),
                    license: vec![],
                }],
            })
            .collect();
        anyhow::Ok(response)
    }
}

fn random_severity() -> Severity {
    let mut rng = rand::thread_rng();
    let severity = rng.gen_range(0..5);
    match severity {
        0 => Severity::Critical,
        1 => Severity::High,
        2 => Severity::Medium,
        3 => Severity::Low,
        4 => Severity::None,
        _ => Severity::None,
    }
}
