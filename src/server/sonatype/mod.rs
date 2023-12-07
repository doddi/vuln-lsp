use core::panic;

use async_trait::async_trait;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

use super::{purl::Purl, Information, Severity, VulnerabilityServer, VulnerabilityVersionInfo};

#[derive(Default)]
pub(crate) struct Sonatype {
    pub client: reqwest::Client,
    base_url: String,
    // TODO Must do better
    username: &'static str,
    password: &'static str,
}

impl Sonatype {
    pub async fn new(base_url: String, application: String) -> Self {
        debug!("Sonatype server created, {base_url}, {application}");

        let username = "admin";
        let password = "admin123";

        Self {
            client: reqwest::Client::new(),
            base_url,
            username,
            password,
        }
    }
}

async fn get_application_id(
    client: &reqwest::Client,
    username: &'static str,
    password: &'static str,
    base_url: &str,
    application: &str,
) -> String {
    trace!("get_application_id entered");
    let request =
        SonatypeClientRequest::GetAllApplications(base_url.to_string(), application.to_string());

    trace!("Converting url");
    let url: Url = request.into();

    trace!("Fetching application id from {url}");
    let builder = reqwest::Client::request(client, reqwest::Method::GET, url)
        .basic_auth(username, Some(password));

    debug!("Fetching application id for: {application}");
    match builder.send().await {
        Ok(response) => match response.json::<ApplicationsGetResponse>().await {
            Ok(applications) => {
                trace!("Applications: {:?}", applications);
                applications
                    .applications
                    .iter()
                    .find(|app| app.name == *application)
                    .unwrap()
                    .id
                    .clone()
            }
            Err(err) => {
                trace!("error parsing get applications response from sonatype: {err}",);
                panic!(
                    "error parsing get applications response from sonatype: {}",
                    err
                );
            }
        },
        Err(err) => {
            trace!("error parsing get applications response from sonatype: {err}",);
            panic!(
                "error sending get applications request to sonatype: {}",
                err
            )
        }
    }
}

#[async_trait]
impl VulnerabilityServer for Sonatype {
    async fn get_versions_for_purl(&self, purl: Purl) -> anyhow::Result<Vec<Purl>> {
        trace!("Geting versions for {}", purl);
        let request = SonatypeClientRequest::ComponentVersions(
            self.base_url.clone(),
            ComponentVersionsRequest { package_url: purl },
        );
        let url: Url = request.clone().into();

        debug!("Sending Sonatype version request to {}", url);
        let builder = reqwest::Client::request(&self.client, reqwest::Method::POST, url)
            .basic_auth(self.username, Some(self.password));

        match builder.json(&request).send().await {
            Ok(response) => {
                debug!("versions response received");

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
        trace!("Getting component information for {:?}", purls);
        let component_details_request = ComponentDetailsRequest {
            components: purls
                .into_iter()
                .map(|purl| WrappedComponentDetailRequest {
                    inner: WrappedPurl { package_url: purl },
                })
                .collect(),
        };

        let request = SonatypeClientRequest::ComponentDetails(
            self.base_url.clone(),
            component_details_request,
        );
        let url: Url = request.clone().into();

        let builder = reqwest::Client::request(&self.client, reqwest::Method::POST, url)
            .basic_auth(self.username, Some(self.password));

        match builder.json(&request).send().await {
            Ok(response) => match response.json::<ComponentDetailsResponse>().await {
                Ok(component_details) => {
                    trace!("{:?}", component_details);
                    anyhow::Ok(
                        component_details
                            .components
                            .into_iter()
                            .map(|component| component.into())
                            .collect(),
                    )
                }
                Err(err) => panic!(
                    "error parsing get component details response from sonatype: {}",
                    err
                ),
            },
            Err(err) => anyhow::Ok(vec![]),
        }
    }
}

#[derive(Clone)]
enum SonatypeClientRequest {
    ComponentVersions(String, ComponentVersionsRequest),
    ComponentDetails(String, ComponentDetailsRequest),
    GetAllApplications(String, String),
}

impl Serialize for SonatypeClientRequest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            SonatypeClientRequest::ComponentVersions(_, request) => request.serialize(serializer),
            SonatypeClientRequest::ComponentDetails(_, request) => request.serialize(serializer),
            SonatypeClientRequest::GetAllApplications(_, _) => {
                panic!("GetAllApplications not implemented")
            }
        }
    }
}

impl From<SonatypeClientRequest> for Url {
    fn from(value: SonatypeClientRequest) -> Self {
        trace!("Converting to url");
        match value {
            SonatypeClientRequest::ComponentVersions(base_url, _) => {
                Url::parse(format!("{base_url}/api/v2/components/versions").as_str()).unwrap()
            }
            SonatypeClientRequest::GetAllApplications(base_url, application) => {
                trace!("base_url: {base_url}, application: {application}");
                match Url::parse(
                    format!("{base_url}/api/v2/applications?publicId={application}").as_str(),
                ) {
                    Ok(url) => url,
                    Err(err) => {
                        warn!("Unable to parse url: {err}");
                        panic!("Error parsing get_all_applications url {err}")
                    }
                }
            }
            SonatypeClientRequest::ComponentDetails(base_url, _) => {
                trace!("base_url: {base_url}");
                match Url::parse(format!("{base_url}/api/v2/components/details").as_str()) {
                    Ok(url) => {
                        trace!("Using: {url}");
                        url
                    }
                    Err(err) => {
                        trace!("Unable to parse url: {err}");
                        panic!("Error pasing get_component_details url {err}");
                    }
                }
            }
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
    pub components: Vec<WrappedComponentDetailRequest>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(transparent)]
struct WrappedComponentDetailRequest {
    inner: WrappedPurl,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WrappedPurl {
    pub package_url: Purl,
}

#[derive(Debug, Deserialize)]
struct ComponentDetailsResponse {
    pub components: Vec<WrappedComponent>,
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct WrappedComponent {
    inner: ComponentDetails,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComponentDetails {
    pub component: Component,
    pub mach_state: String,
    pub relative_popularity: u32,
    pub hygiene_rating: String,
    pub integrity_rating: String,
    pub license_data: Vec<LicenseData>,
    pub security_data: SecurityData,
}

impl From<WrappedComponent> for VulnerabilityVersionInfo {
    fn from(value: WrappedComponent) -> Self {
        VulnerabilityVersionInfo {
            purl: value.inner.component.package_url,
            vulnerabilities: value
                .inner
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
    pub display_name: String,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_compose_version_request() {
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

        let url: Url = request.clone().into();
        assert_eq!(
            url,
            Url::parse("http://localhost:8080/api/v2/components/versions").unwrap()
        );

        let actual = serde_json::to_string(&request).unwrap();
        let expected: String = r#"
            {
                "packageUrl":"pkg:maven/org.apache.commons/commons@1.4.0"
            }
            "#
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

        assert_eq!(actual, expected);
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

    #[test]
    fn can_compose_get_all_applications_request() {
        let request = SonatypeClientRequest::GetAllApplications(
            "http://localhost:8080".to_string(),
            "myapplication".to_string(),
        );

        let url: Url = request.clone().into();
        assert_eq!(
            url,
            Url::parse("http://localhost:8080/api/v2/applications?publicId=myapplication").unwrap()
        );
    }

    #[test]
    fn can_deserialize_get_all_applications_response() {
        let response = r#"
        {
            "applications": [
                {
                    "id": "e1db2d3f4ccf40a38f193183bffdb7e5",
                    "publicId": "app1",
                    "name": "app1",
                    "organizationId": "8162c39152974035b8d66df12f5abe7d",
                    "contactUserName": null,
                    "applicationTags": []
                },
                {
                    "id": "714342759d5d45a28e6b30866b1e244c",
                    "publicId": "app2",
                    "name": "app2",
                    "organizationId": "8162c39152974035b8d66df12f5abe7d",
                    "contactUserName": null,
                    "applicationTags": []
                }
            ]
        }
        "#;

        let actual = serde_json::from_str::<ApplicationsGetResponse>(response).unwrap();

        assert_eq!(actual.applications.len(), 2);
        assert_eq!(
            actual.applications[0].id,
            "e1db2d3f4ccf40a38f193183bffdb7e5"
        );
        assert_eq!(actual.applications[0].public_id, "app1");
        assert_eq!(actual.applications[0].name, "app1");
        assert_eq!(
            actual.applications[0].organization_id,
            "8162c39152974035b8d66df12f5abe7d"
        );
    }

    #[test]
    fn can_compose_get_component_details_request() {
        let request = SonatypeClientRequest::ComponentDetails(
            "http://localhost:8080".to_string(),
            ComponentDetailsRequest {
                components: vec![WrappedComponentDetailRequest {
                    inner: WrappedPurl {
                        package_url: Purl {
                            package: "maven".to_owned(),
                            group_id: "org.apache.commons".to_owned(),
                            artifact_id: "commons".to_owned(),
                            version: "1.4.0".to_owned(),
                        },
                    },
                }],
            },
        );
        let url: Url = request.clone().into();
        assert_eq!(
            url,
            Url::parse("http://localhost:8080/api/v2/components/details").unwrap()
        );

        let expected: String = r#"
            {
                "components": [
                    {
                        "packageUrl":"pkg:maven/org.apache.commons/commons@1.4.0"
                    }
                ]
            }
            "#
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
        let actual = serde_json::to_string(&request).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn can_deserialize_get_component_details_response() {
        let response = r#"
        {
            "components": [
                {
                    "component": {
                        "packageUrl": "pkg:maven/org.apache.commons/commons@1.4.0",
                        "displayName": "org.apache.commons:commons"
                    },
                    "machState": "NOT_EVALUATED",
                    "relativePopularity": 0,
                    "hygieneRating": "NOT_RATED",
                    "integrityRating": "NOT_RATED",
                    "licenseData": [
                        {
                            "licenseId": "Apache-2.0",
                            "licenseName": "Apache License 2.0"
                        }
                    ],
                    "securityData": {
                        "securityIssues": [
                            {
                                "source": "NVD",
                                "reference": "CVE-2018-11771",
                                "severity": 7.5,
                                "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-11771",
                                "threatCategory": "HIGH"
                            },
                            {
                                "source": "NVD",
                                "reference": "CVE-2018-11772",
                                "severity": 7.5,
                                "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-11772",
                                "threatCategory": "HIGH"
                            }
                        ]
                    }
                }
            ]
        }
        "#;
        let actual = serde_json::from_str::<ComponentDetailsResponse>(response).unwrap();
        assert_eq!(actual.components.len(), 1);
        assert_eq!(
            actual.components[0].inner.component.package_url,
            Purl {
                package: "maven".to_owned(),
                group_id: "org.apache.commons".to_owned(),
                artifact_id: "commons".to_owned(),
                version: "1.4.0".to_owned(),
            }
        );
        assert_eq!(
            actual.components[0].inner.component.display_name,
            "org.apache.commons:commons"
        );
        assert_eq!(actual.components[0].inner.mach_state, "NOT_EVALUATED");
        assert_eq!(actual.components[0].inner.relative_popularity, 0);
        assert_eq!(actual.components[0].inner.hygiene_rating, "NOT_RATED");
        assert_eq!(actual.components[0].inner.integrity_rating, "NOT_RATED");
        assert_eq!(
            actual.components[0]
                .inner
                .security_data
                .security_issues
                .len(),
            2
        );
        let security_issues = &actual.components[0].inner.security_data.security_issues;
        assert_eq!(security_issues[0].source, "NVD");
        assert_eq!(security_issues[0].reference, "CVE-2018-11771");
        assert_eq!(security_issues[0].severity, 7.5);
        assert_eq!(
            security_issues[0].url,
            "https://nvd.nist.gov/vuln/detail/CVE-2018-11771"
        );
        assert_eq!(security_issues[0].threat_category, "HIGH");
    }
}
