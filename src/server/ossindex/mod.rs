use crate::{
    common::{errors::VulnLspError, purl::Purl},
    lsp::progress::{ProgressNotifier, ProgressNotifierState},
};

use super::{VulnerabilityInformation, VulnerabilityServer, VulnerabilityVersionInfo};
use anyhow::anyhow;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tower_lsp::lsp_types::Url;
use tracing::{debug, trace, warn};

pub(crate) struct OssIndex {
    pub client: reqwest::Client,
    progress_notifier: ProgressNotifier,
}

impl OssIndex {
    pub fn new(progress_notifier: ProgressNotifier) -> Self {
        Self {
            client: reqwest::Client::new(),
            progress_notifier,
        }
    }

    async fn do_get_component_information(
        &self,
        purls: &[Purl],
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>> {
        trace!("getting component information from ossindex");

        let _ = self
            .progress_notifier
            .send_progress(ProgressNotifierState::Start(
                "OssIndex".to_string(),
                "OssIndex".to_string(),
                Some("building...".to_string()),
            ))
            .await;

        // OssIndex does not like any qualifiers being specified so removed them
        let oss_purls = purls
            .iter()
            .map(|purl| Purl {
                purl_type: None,
                package: purl.clone().package,
                group_id: purl.clone().group_id,
                artifact_id: purl.clone().artifact_id,
                version: purl.clone().version,
            })
            .collect();

        let request = OssClientRequest::ComponentReport(ComponentReportRequest {
            coordinates: oss_purls,
        });

        let url: Url = request.clone().into();

        debug!("Sending OssIndex request to {}", url);
        let builder = reqwest::Client::request(&self.client, reqwest::Method::POST, url);

        match builder.json(&request).send().await {
            Ok(response) => {
                debug!("response received from OssIndex *");

                let _ = self
                    .progress_notifier
                    .send_progress(ProgressNotifierState::Update(
                        "OssIndex".to_string(),
                        None,
                        50,
                    ))
                    .await;

                match response.json::<Vec<ComponentReport>>().await {
                    Ok(payload) => {
                        let data = payload
                            .into_iter()
                            .map(|component_report| {
                                let purl = match match_against_purl(
                                    component_report.coordinates.clone(),
                                    purls,
                                ) {
                                    Some(purl) => purl,
                                    None => &component_report.coordinates,
                                };

                                ComponentReport {
                                    coordinates: purl.clone(),
                                    ..component_report
                                }
                                .into()
                            })
                            .collect();
                        let _ = self
                            .progress_notifier
                            .send_progress(ProgressNotifierState::Complete("OssIndex".to_string()))
                            .await;

                        anyhow::Ok(data)
                    }
                    Err(err) => {
                        let _ = self
                            .progress_notifier
                            .send_progress(ProgressNotifierState::Complete("OssIndex".to_string()))
                            .await;

                        warn!("error parsing response from ossindex: {}", err);
                        Err(anyhow!(VulnLspError::ServerParse))
                    }
                }
            }
            Err(err) => {
                let _ = self
                    .progress_notifier
                    .send_progress(ProgressNotifierState::Complete("OssIndex".to_string()))
                    .await;

                warn!("error sending request to ossindex: {}", err);
                Err(anyhow!(VulnLspError::ServerRequest(request.into())))
            }
        }
    }
}

fn match_against_purl(oss_index_purl: Purl, original_purls: &[Purl]) -> Option<&Purl> {
    original_purls.iter().find(|purl| {
        oss_index_purl.package == purl.package
            && oss_index_purl.group_id == purl.group_id
            && oss_index_purl.artifact_id == purl.artifact_id
            && oss_index_purl.version == purl.version
    })
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
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

#[derive(Clone, Debug, Serialize)]
struct ComponentReportRequest {
    pub coordinates: Vec<Purl>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ComponentReport {
    pub coordinates: Purl,
    pub description: Option<String>,
    pub reference: String,
    pub vulnerabilities: Vec<ComponentReportVulnerability>,
}

impl From<ComponentReport> for VulnerabilityVersionInfo {
    fn from(value: ComponentReport) -> Self {
        Self {
            purl: value.coordinates,
            vulnerabilities: value
                .vulnerabilities
                .into_iter()
                .map(|x| x.into())
                .collect(),
        }
    }
}

impl From<ComponentReportVulnerability> for VulnerabilityInformation {
    fn from(value: ComponentReportVulnerability) -> Self {
        Self {
            severity: calculate_violation_level(value.cvss_score),
            summary: value.title,
            detail: value.description,
            license: vec![],
        }
    }
}

fn calculate_violation_level(cvss_score: f32) -> super::Severity {
    if cvss_score <= 3.9 && cvss_score > 0.0 {
        super::Severity::Low
    } else if cvss_score > 3.9 && cvss_score <= 6.9 {
        super::Severity::Medium
    } else if cvss_score > 6.9 && cvss_score <= 8.9 {
        super::Severity::High
    } else if cvss_score > 9.0 {
        super::Severity::Critical
    } else {
        super::Severity::None
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ComponentReportVulnerability {
    pub id: String,
    #[serde(rename = "displayName")]
    display_name: String,
    title: String,
    description: String,
    #[serde(rename = "cvssScore")]
    cvss_score: f32,
    #[serde(rename = "cvssVector")]
    cvss_vector: String,
    cwe: String,
    cve: String,
    reference: String,

    #[serde(rename = "versionRanges")]
    version_ranges: Option<Vec<String>>,
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

#[async_trait]
impl VulnerabilityServer for OssIndex {
    async fn get_component_information(
        &self,
        purls: &[Purl],
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>> {
        self.do_get_component_information(purls).await
    }

    async fn get_versions_for_purl(&self, purl: Purl) -> anyhow::Result<Vec<Purl>> {
        // TODO: figure out how to get versions from ossindex
        anyhow::Ok(vec![purl])
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn single_purl_payload() {
        let purls = vec![Purl {
            package: "maven".to_string(),
            group_id: Some("org.apache.commons".to_string()),
            artifact_id: "commons-lang3".to_string(),
            version: "3.9".to_string(),
            purl_type: None,
        }];

        let request =
            OssClientRequest::ComponentReport(ComponentReportRequest { coordinates: purls });
        let url: Url = request.clone().into();

        assert_eq!(
            url,
            Url::parse("https://ossindex.sonatype.org/api/v3/component-report").unwrap()
        );

        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            trim_payload(
                r#"
                {
                    "coordinates":[
                        "pkg:maven/org.apache.commons/commons-lang3@3.9"
                    ]
                }
                "#
            )
        );
    }

    #[test]
    fn multi_purl_payload() {
        let purls = vec![
            Purl {
                package: "maven".to_string(),
                group_id: Some("org.apache.commons".to_string()),
                artifact_id: "commons-lang3".to_string(),
                version: "3.9".to_string(),
                purl_type: None,
            },
            Purl {
                package: "maven".to_string(),
                group_id: Some("org.foo".to_string()),
                artifact_id: "bar".to_string(),
                version: "1.0.0".to_string(),
                purl_type: None,
            },
        ];

        let request =
            OssClientRequest::ComponentReport(ComponentReportRequest { coordinates: purls });
        let url: Url = request.clone().into();

        assert_eq!(
            url,
            Url::parse("https://ossindex.sonatype.org/api/v3/component-report").unwrap()
        );

        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            trim_payload(
                r#"
                {
                    "coordinates":[
                        "pkg:maven/org.apache.commons/commons-lang3@3.9",
                        "pkg:maven/org.foo/bar@1.0.0"
                    ]
                }
                "#
            )
        );
    }

    #[test]
    fn can_deserialize_payload() {
        let response = r#"
            [
                {
                    "coordinates": "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1",
                    "description": "",
                    "reference": "https://ossindex.sonatype.org/component/pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                    "vulnerabilities": []
                }
            ]
        "#;

        let response = serde_json::from_str::<Vec<ComponentReport>>(response).unwrap();

        assert_eq!(response.len(), 1);
    }

    #[test]
    fn can_deserialize_with_vulnerabilities() {
        let expected = r#"
            [
            {
                "coordinates": "pkg:maven/org.apache.struts/struts-core@1.3.10",
                "description": "test description",
                "reference": "https://ossindex.sonatype.org/component/pkg:maven/org.apache.struts/struts-core@1.3.10?utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                "vulnerabilities": [
                {
                    "id": "CVE-2014-0114",
                    "displayName": "CVE-2014-0114",
                    "title": "[CVE-2014-0114] CWE-20: Improper Input Validation",
                    "description": "Apache Commons BeanUtils, as distributed in lib/commons-beanutils-1.8.0.jar in Apache Struts 1.x through 1.3.10 and in other products requiring commons-beanutils through 1.9.2, does not suppress the class property, which allows remote attackers to \"manipulate\" the ClassLoader and execute arbitrary code via the class parameter, as demonstrated by the passing of this parameter to the getClass method of the ActionForm object in Struts 1.",
                    "cvssScore": 7.5,
                    "cvssVector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    "cwe": "CWE-20",
                    "cve": "CVE-2014-0114",
                    "reference": "https://ossindex.sonatype.org/vulnerability/CVE-2014-0114?component-type=maven&component-name=org.apache.struts%2Fstruts-core&utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                    "externalReferences": [
                    "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0114",
                    "http://www.rapid7.com/db/modules/exploit/multi/http/struts_code_exec_classloader",
                    "https://issues.apache.org/jira/browse/BEANUTILS-463"
                    ]
                },
                {
                    "id": "CVE-2015-0899",
                    "displayName": "CVE-2015-0899",
                    "title": "[CVE-2015-0899] CWE-20: Improper Input Validation",
                    "description": "The MultiPageValidator implementation in Apache Struts 1 1.1 through 1.3.10 allows remote attackers to bypass intended access restrictions via a modified page parameter.",
                    "cvssScore": 7.5,
                    "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    "cwe": "CWE-20",
                    "cve": "CVE-2015-0899",
                    "reference": "https://ossindex.sonatype.org/vulnerability/CVE-2015-0899?component-type=maven&component-name=org.apache.struts%2Fstruts-core&utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                    "externalReferences": [
                    "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-0899",
                    "http://jvndb.jvn.jp/en/contents/2015/JVNDB-2015-000042.html",
                    "https://en.osdn.jp/projects/terasoluna/wiki/StrutsPatch2-EN"
                    ]
                },
                {
                    "id": "CVE-2016-1181",
                    "displayName": "CVE-2016-1181",
                    "title": "[CVE-2016-1181] CWE-94: Improper Control of Generation of Code ('Code Injection')",
                    "description": "ActionServlet.java in Apache Struts 1 1.x through 1.3.10 mishandles multithreaded access to an ActionForm instance, which allows remote attackers to execute arbitrary code or cause a denial of service (unexpected memory access) via a multipart request, a related issue to CVE-2015-0899.",
                    "cvssScore": 8.1,
                    "cvssVector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cwe": "CWE-94",
                    "cve": "CVE-2016-1181",
                    "reference": "https://ossindex.sonatype.org/vulnerability/CVE-2016-1181?component-type=maven&component-name=org.apache.struts%2Fstruts-core&utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                    "externalReferences": [
                    "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-1181",
                    "http://jvn.jp/en/jp/JVN03188560/index.html",
                    "https://security-tracker.debian.org/tracker/CVE-2016-1181"
                    ]
                },
                {
                    "id": "CVE-2016-1182",
                    "displayName": "CVE-2016-1182",
                    "title": "[CVE-2016-1182] CWE-20: Improper Input Validation",
                    "description": "ActionServlet.java in Apache Struts 1 1.x through 1.3.10 does not properly restrict the Validator configuration, which allows remote attackers to conduct cross-site scripting (XSS) attacks or cause a denial of service via crafted input, a related issue to CVE-2015-0899.",
                    "cvssScore": 8.2,
                    "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H",
                    "cwe": "CWE-20",
                    "cve": "CVE-2016-1182",
                    "reference": "https://ossindex.sonatype.org/vulnerability/CVE-2016-1182?component-type=maven&component-name=org.apache.struts%2Fstruts-core&utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                    "externalReferences": [
                    "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-1182",
                    "http://jvn.jp/en/jp/JVN65044642/index.html",
                    "https://security-tracker.debian.org/tracker/CVE-2016-1182"
                    ]
                }
                ]
            }
            ]
            "#;

        let response = serde_json::from_str::<Vec<ComponentReport>>(expected).unwrap();

        let purl: Purl =
            serde_json::from_str("\"pkg:maven/org.apache.struts/struts-core@1.3.10\"").unwrap();
        assert_eq!(response[0].coordinates, purl);
        assert_eq!(response[0].description.clone().unwrap(), "test description");
        assert_eq!(response[0].vulnerabilities.len(), 4);

        let vulnerabilities = &response[0].vulnerabilities;
        assert_eq!(vulnerabilities[0].id, "CVE-2014-0114");
        assert_eq!(vulnerabilities[0].display_name, "CVE-2014-0114");
        let title = "[CVE-2014-0114] CWE-20: Improper Input Validation";
        let description = "Apache Commons BeanUtils, as distributed in lib/commons-beanutils-1.8.0.jar in Apache Struts 1.x through 1.3.10 and in other products requiring commons-beanutils through 1.9.2, does not suppress the class property, which allows remote attackers to \"manipulate\" the ClassLoader and execute arbitrary code via the class parameter, as demonstrated by the passing of this parameter to the getClass method of the ActionForm object in Struts 1.";
        assert_eq!(vulnerabilities[0].title, title);
        assert_eq!(vulnerabilities[0].description, description);
        assert_eq!(vulnerabilities[0].cvss_score, 7.5);
        assert_eq!(vulnerabilities[0].cvss_vector, "AV:N/AC:L/Au:N/C:P/I:P/A:P");
        assert_eq!(vulnerabilities[0].cwe, "CWE-20");
        assert_eq!(vulnerabilities[0].cve, "CVE-2014-0114");
        assert_eq!(vulnerabilities[0].reference, "https://ossindex.sonatype.org/vulnerability/CVE-2014-0114?component-type=maven&component-name=org.apache.struts%2Fstruts-core&utm_source=mozilla&utm_medium=integration&utm_content=5.0");
        assert_eq!(vulnerabilities[0].external_references.len(), 3);
    }

    fn trim_payload(payload: &str) -> String {
        payload.replace(" ", "").replace("\n", "")
    }
}
