#![allow(unused)]
use anyhow::anyhow;
use async_trait::async_trait;
use core::panic;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

use super::{purl::Purl, Information, Severity, VulnerabilityServer, VulnerabilityVersionInfo};
use crate::{server, VulnLspError};

pub(crate) struct Sonatype {
    pub client: reqwest::Client,
    cacher: Arc<Mutex<server::cacher::Cacher<Purl, VulnerabilityVersionInfo>>>,

    base_url: String,
    // TODO: Must do better
    username: &'static str,
    password: &'static str,
}

impl Sonatype {
    pub async fn new(base_url: String) -> Self {
        debug!("Sonatype server created, {base_url}");

        let username = "admin";
        let password = "admin123";

        Self {
            client: reqwest::Client::new(),
            cacher: Arc::new(Mutex::new(server::cacher::Cacher::new())),
            base_url,
            username,
            password,
        }
    }

    async fn do_get_component_information(
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

        let builder = reqwest::Client::request(&self.client, reqwest::Method::POST, url.clone())
            .basic_auth(self.username, Some(self.password));

        // trace!("about to send {:?} to {:?}", request, url);
        match builder.json(&request).send().await {
            Ok(response) => match response.json::<ComponentDetailsResponse>().await {
                Ok(component_details) => {
                    trace!("component details {:?}", component_details);
                    anyhow::Ok(
                        component_details
                            .component_details
                            .into_iter()
                            .map(|component| component.inner.into())
                            .collect(),
                    )
                }
                Err(err) => {
                    warn!("Component Details response error {}", err);
                    Err(anyhow!(VulnLspError::ServerParse))
                }
            },
            Err(err) => {
                warn!("Component Details response error: {err}");
                Err(anyhow!(VulnLspError::ServerRequest(url)))
            }
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
            ComponentVersionsRequest {
                package_url: purl.clone(),
            },
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
                        let purls = payload
                            .versions
                            .into_iter()
                            .map(|version| {
                                let _purl = purl.clone();
                                Purl {
                                    package: _purl.package,
                                    group_id: _purl.group_id,
                                    artifact_id: _purl.artifact_id,
                                    version,
                                    purl_type: _purl.purl_type,
                                }
                            })
                            .collect();
                        anyhow::Ok(purls)
                    }
                    Err(err) => {
                        warn!("error parsing response from lifecycle: {}", err);
                        anyhow::Ok(vec![])
                    }
                }
            }
            Err(err) => {
                warn!("error sending request to lifecycle: {}", err);
                anyhow::Ok(vec![])
            }
        }
    }

    async fn get_component_information(
        &self,
        purls: Vec<Purl>,
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>> {
        self.do_get_component_information(purls).await
    }
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone, Serialize)]
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
#[serde(rename_all = "camelCase")]
struct ComponentDetailsResponse {
    pub component_details: Vec<WrappedComponentDetails>,
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct WrappedComponentDetails {
    pub inner: ComponentDetails,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComponentDetails {
    pub component: Component,
    pub match_state: String,
    // pub relative_popularity: u32,
    // pub hygiene_rating: String,
    // pub integrity_rating: String,
    // pub license_data: Vec<LicenseData>,
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
            license: vec![],
        }
    }
}

impl From<f32> for Severity {
    fn from(value: f32) -> Self {
        if value > 9.0 {
            Severity::Critical
        } else if value > 7.0 {
            Severity::High
        } else if value > 4.0 {
            Severity::Medium
        } else if value > 0.0 {
            Severity::Low
        } else {
            Severity::None
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
                    group_id: Some("org.apache.commons".to_owned()),
                    artifact_id: "commons".to_owned(),
                    version: "1.4.0".to_owned(),
                    purl_type: Some("jar".to_string()),
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
                "packageUrl":"pkg:maven/org.apache.commons/commons@1.4.0?type=jar"
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
                            group_id: Some("org.apache.commons".to_owned()),
                            artifact_id: "commons".to_owned(),
                            version: "1.4.0".to_owned(),
                            purl_type: Some("jar".to_string()),
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
                        "packageUrl":"pkg:maven/org.apache.commons/commons@1.4.0?type=jar"
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
            "componentDetails": [
                {
                    "component": {
                        "packageUrl": "pkg:maven/tomcat/tomcat-util@5.5.23?type=jar",
                        "hash": "1249e25aebb15358bedd",
                        "componentIdentifier": {
                            "format": "maven",
                            "coordinates": {
                                "artifactId": "tomcat-util",
                                "classifier": "",
                                "extension": "jar",
                                "groupId": "tomcat",
                                "version": "5.5.23"
                            }
                        },
                        "displayName": "tomcat : tomcat-util : 5.5.23"
                    },
                    "matchState": "exact",
                    "catalogDate": "2008-01-24T04:19:17.000Z",
                    "relativePopularity": 73,
                    "licenseData": {
                        "declaredLicenses": [
                            {
                                "licenseId": "Apache-2.0",
                                "licenseName": "Apache-2.0"
                            }
                        ],
                        "observedLicenses": [
                            {
                                "licenseId": "No-Source-License",
                                "licenseName": "No Source License"
                            }
                        ],
                        "effectiveLicenses": [
                            {
                                "licenseId": "Apache-2.0",
                                "licenseName": "Apache-2.0"
                            }
                        ]
                    },
                    "integrityRating": null,
                    "hygieneRating": null,
                    "securityData": {
                        "securityIssues": [
                            {
                                "source": "cve",
                                "reference": "CVE-2007-3385",
                                "severity": 4.3,
                                "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3385",
                                "threatCategory": "severe"
                            },
                            {
                                "source": "cve",
                                "reference": "CVE-2007-5333",
                                "severity": 5.0,
                                "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5333",
                                "threatCategory": "severe"
                            },
                            {
                                "source": "cve",
                                "reference": "CVE-2011-2526",
                                "severity": 4.4,
                                "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2526",
                                "threatCategory": "severe"
                            },
                            {
                                "source": "cve",
                                "reference": "CVE-2012-0022",
                                "severity": 5.0,
                                "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0022",
                                "threatCategory": "severe"
                            },
                            {
                                "source": "cve",
                                "reference": "CVE-2014-0099",
                                "severity": 4.3,
                                "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0099",
                                "threatCategory": "severe"
                            },
                            {
                                "source": "cve",
                                "reference": "CVE-2015-5345",
                                "severity": 5.3,
                                "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5345",
                                "threatCategory": "severe"
                            },
                            {
                                "source": "cve",
                                "reference": "CVE-2016-6794",
                                "severity": 5.3,
                                "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6794",
                                "threatCategory": "severe"
                            },
                            {
                                "source": "cve",
                                "reference": "CVE-2017-5647",
                                "severity": 7.5,
                                "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5647",
                                "threatCategory": "critical"
                            }
                        ]
                    },
                    "projectData": {
                        "firstReleaseDate": "2005-08-01T10:50:32.000+01:00",
                        "lastReleaseDate": "2008-01-24T04:19:17.000Z",
                        "projectMetadata": {
                            "description": "The Apache Software Foundation provides support for the Apache community of open-source software projects.\n    The Apache projects are characterized by a collaborative, consensus based development process, an open and\n    pragmatic software license, and a desire to create high quality software that leads the way in its field.\n    We consider ourselves not simply a group of projects sharing a server, but rather a community of developers\n    and users.",
                            "organization": "The Apache Software Foundation"
                        },
                        "sourceControlManagement": {
                            "scmUrl": "https://svn.apache.org/repos/asf/maven/pom/tags/apache-4/tomcat-parent/tomcat-util"
                        }
                    }
                }
            ]
        }
        "#;
        let actual = serde_json::from_str::<ComponentDetailsResponse>(response).unwrap();
        assert_eq!(actual.component_details.len(), 1);
        assert_eq!(
            actual.component_details[0].inner.component.package_url,
            Purl {
                package: "maven".to_owned(),
                group_id: Some("tomcat".to_owned()),
                artifact_id: "tomcat-util".to_owned(),
                version: "5.5.23".to_owned(),
                purl_type: Some("jar".to_string()),
            }
        );
        assert_eq!(
            actual.component_details[0].inner.component.display_name,
            "tomcat : tomcat-util : 5.5.23"
        );
        assert_eq!(actual.component_details[0].inner.match_state, "exact");
        assert_eq!(
            actual.component_details[0]
                .inner
                .security_data
                .security_issues
                .len(),
            8
        );
        let security_issues = &actual.component_details[0]
            .inner
            .security_data
            .security_issues;
        assert_eq!(security_issues[0].source, "cve");
        assert_eq!(security_issues[0].reference, "CVE-2007-3385");
        assert_eq!(security_issues[0].severity, 4.3);
        assert_eq!(
            security_issues[0].url,
            "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3385",
        );
        assert_eq!(security_issues[0].threat_category, "severe");
    }
}
