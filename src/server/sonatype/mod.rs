use async_trait::async_trait;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

use super::{purl::Purl, Information, Severity, VulnerabilityServer, VulnerabilityVersionInfo};

#[derive(Default)]
pub(crate) struct Sonatype {
    pub client: reqwest::Client,
    base_url: String,
    application_id: String,
}

impl Sonatype {
    pub async fn new(base_url: String, application: String) -> Self {
        let client = reqwest::Client::new();
        let application_id = get_application_id(&client, &base_url, &application).await;

        Self {
            client: reqwest::Client::new(),
            base_url,
            application_id,
        }
    }
}

async fn get_application_id(client: &reqwest::Client, base_url: &str, application: &str) -> String {
    let request =
        SonatypeClientRequest::GetAllApplications(base_url.to_string(), application.to_string());

    let url: Url = request.into();

    let builder = reqwest::Client::request(client, reqwest::Method::GET, url);

    match builder.send().await {
        Ok(response) => match response.json::<ApplicationsGetResponse>().await {
            Ok(applications) => applications
                .applications
                .iter()
                .find(|app| app.name == *application)
                .unwrap()
                .id
                .clone(),
            Err(err) => panic!(
                "error parsing get applications response from sonatype: {}",
                err
            ),
        },
        Err(err) => panic!(
            "error sending get applications request to sonatype: {}",
            err
        ),
    }
}

#[async_trait]
impl VulnerabilityServer for Sonatype {
    async fn get_versions_for_purl(&self, purl: Purl) -> anyhow::Result<Vec<Purl>> {
        let request = SonatypeClientRequest::ComponentVersions(
            self.base_url.clone(),
            ComponentVersionsRequest { package_url: purl },
        );
        let url: Url = request.clone().into();

        debug!("Sending Sonatype version request to {}", url);
        let builder = reqwest::Client::request(&self.client, reqwest::Method::POST, url);

        match builder.json(&request).send().await {
            Ok(response) => {
                debug!("response received from OssIndex");

                match response.json::<ComponentVersionsResponse>().await {
                    Ok(payload) => {
                        trace!("payload: {:?}", payload);
                        anyhow::Ok(vec![])
                    }
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

    async fn get_component_information(
        &self,
        purls: Vec<Purl>,
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>> {
        let component_evaluation_request = ComponentDetailsRequest {
            components: purls
                .into_iter()
                .map(|purl| WrappedPurl { package_url: purl })
                .collect(),
        };

        let request = SonatypeClientRequest::ComponentDetails(
            self.base_url.clone(),
            self.application_id.clone(),
            component_evaluation_request,
        );
        let url: Url = request.clone().into();

        let builder = reqwest::Client::request(&self.client, reqwest::Method::POST, url);

        match builder.json(&request).send().await {
            Ok(response) => match response.json::<ComponentDetailsResponse>().await {
                Ok(component_details) => anyhow::Ok(
                    component_details
                        .components
                        .into_iter()
                        .map(|component| component.into())
                        .collect(),
                ),
                Err(err) => panic!(
                    "error parsing get component details response from sonatype: {}",
                    err
                ),
            },
            Err(err) => anyhow::Ok(vec![]),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
enum SonatypeClientRequest {
    ComponentVersions(String, ComponentVersionsRequest),
    ComponentDetails(String, String, ComponentDetailsRequest),
    GetAllApplications(String, String),
}

impl From<SonatypeClientRequest> for Url {
    fn from(value: SonatypeClientRequest) -> Self {
        match value {
            SonatypeClientRequest::ComponentVersions(base_url, _) => {
                Url::parse(format!("{base_url}/api/v2/components/versions").as_str()).unwrap()
            }
            SonatypeClientRequest::GetAllApplications(base_url, application) => Url::parse(
                format!("{base_url}/api/v2/applications?publicId={application}").as_str(),
            )
            .unwrap(),
            SonatypeClientRequest::ComponentDetails(base_url, application_id, _) => Url::parse(
                format!("{base_url}/api/v2/evaluation/applications/{application_id}").as_str(),
            )
            .unwrap(),
        }
    }
}

#[derive(Clone, Serialize)]
struct ComponentVersionsRequest {
    #[serde(rename = "packageUrl")]
    pub package_url: Purl,
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct ComponentVersionsResponse {
    pub versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ApplicationsGetResponse {
    applications: Vec<Application>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Application {
    pub id: String,
    pub public_id: String,
    pub name: String,
    pub organization_id: String,
}

#[derive(Debug, Serialize, Clone)]
struct ComponentDetailsRequest {
    pub components: Vec<WrappedPurl>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(transparent)]
struct WrappedPurl {
    pub package_url: Purl,
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct ComponentDetailsResponse {
    pub components: Vec<ComponentDetails>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComponentDetails {
    pub component: Component,
    pub mach_state: String,
    pub relative_popularity: u32,
    pub hygiene_rating: String,
    pub integrity_rating: String,
    pub licnse_data: Vec<LicenseData>,
    pub security_data: SecurityData,
}

impl From<ComponentDetails> for VulnerabilityVersionInfo {
    fn from(value: ComponentDetails) -> Self {
        VulnerabilityVersionInfo {
            purl: value.component.package_url,
            vulnerabilities: value
                .security_data
                .security_issues
                .into_iter()
                .map(|s| s.into())
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LicenseData {
    pub license_id: String,
    pub license_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecurityData {
    pub security_issues: Vec<SecurityIssue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecurityIssue {
    pub source: String,
    pub reference: String,
    pub severity: f32,
    pub url: String,
    pub threat_category: String,
}

impl From<SecurityIssue> for Information {
    fn from(value: SecurityIssue) -> Self {
        Information {
            severity: Severity::from(value.severity),
            summary: value.threat_category,
            detail: value.url,
        }
    }
}

impl From<f32> for Severity {
    fn from(value: f32) -> Self {
        match value {
            0.0..=1.0 => Severity::None,
            1.1..=3.9 => Severity::Low,
            4.0..=6.9 => Severity::Medium,
            7.0..=8.9 => Severity::High,
            9.0..=10.0 => Severity::Critical,
            _ => panic!("invalid severity value: {}", value),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Component {
    pub package_url: Purl,
    pub diaply_name: String,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_compose_url() {
        let request = SonatypeClientRequest::ComponentVersions(
            "http://localhost:8080".to_string(),
            ComponentVersionsRequest {
                package_url: Purl {
                    package: "maven".to_owned(),
                    group_id: "org.apache.commons".to_owned(),
                    artifact_id: "commons".to_owned(),
                    version: "1.4.0".to_owned(),
                },
            },
        );

        let url: Url = request.into();
        assert_eq!(
            url.as_str(),
            "http://localhost:8080/api/v2/components/versions"
        );
    }

    #[test]
    fn can_serialize_component_version_request() {
        let request = SonatypeClientRequest::ComponentVersions(
            "http://localhost".to_string(),
            ComponentVersionsRequest {
                package_url: Purl {
                    package: "maven".to_owned(),
                    group_id: "org.apache.commons".to_owned(),
                    artifact_id: "commons".to_owned(),
                    version: "1.4.0".to_owned(),
                },
            },
        );

        let actual = serde_json::to_string(&request).unwrap();
        assert_eq!(
            actual,
            r#"{"packageUrl":"pkg:maven/org.apache.commons/commons@1.4.0"}"#
        );
    }

    #[test]
    fn can_deserialize_versions_response() {
        let response = r#"
        [
            "1.0.0",
            "1.0.1",
            "3.0.0"
        ]"#;

        let actual = serde_json::from_str::<ComponentVersionsResponse>(response).unwrap();

        assert_eq!(actual.versions.len(), 3);
        assert!(actual.versions.contains(&"1.0.0".to_string()));
        assert!(actual.versions.contains(&"1.0.1".to_string()));
        assert!(actual.versions.contains(&"3.0.0".to_string()));
    }
}
