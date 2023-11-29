use async_trait::async_trait;
use tower_lsp::lsp_types::Url;

use super::{purl::Purl, VulnerabilityInformationResponse, VulnerabilityServer};

struct OssIndex;

enum OssClient {
    ComponentReport(Vec<Purl>),
}

impl From<OssClient> for Url {
    fn from(value: OssClient) -> Self {
        match value {
            OssClient::ComponentReport(_) => {
                Url::parse("https://ossindex.sonatype.org/api/v3/component-report").unwrap()
            }
        }
    }
}

#[async_trait]
impl VulnerabilityServer for OssIndex {
    async fn get_version_information_for_purls(
        &self,
        purls: Vec<Purl>,
    ) -> Vec<VulnerabilityInformationResponse> {
        todo!()
    }
}
