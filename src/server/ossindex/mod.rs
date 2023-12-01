use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tower_lsp::lsp_types::Url;
use tracing::{debug, warn};

use super::{purl::Purl, Information, VulnerabilityServer, VulnerabilityVersionInfo};

pub(crate) struct OssIndex {
    pub client: reqwest::Client,
}

impl OssIndex {}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ComponentReportRequest {
    pub coordinates: Vec<Purl>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ComponentReport {
    pub coordinates: Purl,
    pub description: String,
    pub reference: String,
    pub vulnerabilities: Vec<ComponentReportVulnerability>,
}

impl From<ComponentReport> for VulnerabilityVersionInfo {
    fn from(value: ComponentReport) -> Self {
        Self {
            purl: value.coordinates,
            information: Information {
                severity: calculate_violation_level(&value.vulnerabilities),
                summary: summarize_violations(&value.vulnerabilities),
                detail: detail_violations(&value.vulnerabilities),
            },
        }
    }
}

fn detail_violations(vulnerabilities: &[ComponentReportVulnerability]) -> String {
    todo!()
}

fn summarize_violations(vulnerabilities: &[ComponentReportVulnerability]) -> String {
    todo!()
}

fn calculate_violation_level(vulnerabilities: &[ComponentReportVulnerability]) -> super::Severity {
    todo!()
}

// impl From<ComponentReportVulnerability> for VulnerabilityVersionInfo {
//     fn from(value: ComponentReportVulnerability) -> Self {
//         Self {
//             version: todo!(),
//             severity: todo!(),
//             information: todo!(),
//         }
//     }
// }

#[derive(Debug, Serialize, Deserialize)]
struct ComponentReportVulnerability {
    pub id: String,
    #[serde(rename = "displayName")]
    display_name: String,
    title: String,
    #[serde(rename = "cvssScore")]
    cvss_score: f32,
    #[serde(rename = "cvssVector")]
    cvss_vector: String,
    cwe: String,
    cve: String,
    reference: String,

    #[serde(rename = "versionRanges")]
    version_ranges: Vec<String>,
    #[serde(rename = "externalReferences")]
    external_references: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Version {
    pub value: String,
    #[serde(rename = "buildTimeStamp")]
    pub build_timestamp: String,
    #[serde(rename = "buildTag")]
    pub build_tag: String,
    #[serde(rename = "build_notes")]
    pub build_notes: String,
}

#[derive(Clone, Serialize)]
enum OssClientRequest {
    ComponentReport(ComponentReportRequest),
}

impl From<OssClientRequest> for Url {
    fn from(val: OssClientRequest) -> Self {
        match val {
            OssClientRequest::ComponentReport(_) => {
                Url::parse("https://ossindex.sonatype.org/api/v3/component-report").unwrap()
            }
        }
    }
}

// impl From<OssClientRequest> for reqwest::Request {
//     fn from(val: OssClientRequest) -> Self {
//         match &val {
//             OssClientRequest::ComponentReport(component_report_request) => {
//                 let request = reqwest::Request::new(reqwest::Method::POST, val.into());
//                 request
//             }
//         }
//     }
// }

// impl Serialize for OssClientRequest {
//     fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//         match self {
//             OssClientRequest::ComponentReport(request) => request.serialize(serializer),
//         }
//     }
// }

#[async_trait]
impl VulnerabilityServer for OssIndex {
    async fn get_component_information(
        &self,
        purls: Vec<Purl>,
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>> {
        let request =
            OssClientRequest::ComponentReport(ComponentReportRequest { coordinates: purls });

        let url: Url = request.clone().into();

        let builder = reqwest::Client::request(&self.client, reqwest::Method::POST, url);

        match builder.json(&request).send().await {
            Ok(response) => {
                debug!("response received from OssIndex");

                match response.json::<Vec<ComponentReport>>().await {
                    Ok(payload) => anyhow::Ok(payload.into_iter().map(|x| x.into()).collect()),
                    Err(err) => {
                        warn!("error parsing response from ossindex: {}", err);
                        anyhow::Ok(vec![])
                    }
                }
            }
            Err(err) => {
                warn!("error sending request to ossindex: {}", err);
                anyhow::Ok(vec![])
            }
        }
    }

    async fn get_versions_for_purl(
        &self,
        _purl: Purl,
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>> {
        todo!()
    }
}
