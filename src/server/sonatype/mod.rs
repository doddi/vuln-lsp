use async_trait::async_trait;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

use super::{purl::Purl, VulnerabilityServer, VulnerabilityVersionInfo};

#[derive(Default)]
pub(crate) struct Sonatype {
    pub client: reqwest::Client,
    pub base_url: String,
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
        _purls: Vec<Purl>,
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>> {
        todo!()
    }
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
enum SonatypeClientRequest {
    ComponentVersions(String, ComponentVersionsRequest),
}

impl From<SonatypeClientRequest> for Url {
    fn from(value: SonatypeClientRequest) -> Self {
        match value {
            SonatypeClientRequest::ComponentVersions(base_url, _) => {
                Url::parse(format!("{base_url}/api/v2/components/versions").as_str()).unwrap()
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_serialize_component_version_request() {
        let request = SonatypeClientRequest::ComponentVersions(ComponentVersionsRequest {
            package_url: Purl {
                package: "maven".to_owned(),
                group_id: "org.apache.commons".to_owned(),
                artifact_id: "commons".to_owned(),
                version: "1.4.0".to_owned(),
            },
        });

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
