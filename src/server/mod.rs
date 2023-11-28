use crate::Purl;

#[derive(Debug)]
pub struct VulnerabilityInformationResponse {
    pub purl: Purl,
    pub versions: Vec<VulnerabilityVersionInfo>,
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct Information {
    pub summary: String,
    pub detail: String,
}

pub async fn get_version_information_for_purl(purl: &Purl) -> VulnerabilityInformationResponse {
    // TODO Fetch from the real endpoint
    VulnerabilityInformationResponse {
        purl: purl.clone(),
        versions: vec![
            VulnerabilityVersionInfo {
                version: "1.0.0".to_string(),
                severity: Severity::High,
                information: Information {
                    summary:    "This is a vulnerability header or short description".to_string(),
                    detail:     "This is a much more details description of the vulnerability which may include things such as links".to_string(),
                },
            },
            VulnerabilityVersionInfo {
                version: "2.0.0".to_string(),
                severity: Severity::None,
                information: Information {
                    summary:    "short description".to_string(),
                    detail:     "This is a much more details description of the vulnerability which may include things such as links".to_string(),
                },
            }
        ],
    }
}

pub async fn get_vulnerability_information_for_purls(
    purls: Vec<Purl>,
) -> Vec<VulnerabilityInformationResponse> {
    futures::future::join_all(
        purls
            .iter()
            .map(|purl| get_version_information_for_purl(&purl)),
    )
    .await
}
