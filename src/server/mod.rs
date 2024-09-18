use async_trait::async_trait;

use crate::common::purl::Purl;

pub(crate) mod cacher;
pub(crate) mod dummy;
pub(crate) mod ossindex;
pub(crate) mod sonatype;

#[derive(Debug, Clone)]
pub enum VulnerableServerType {
    Dummy,
    OssIndex,
    Sonatype { base_url: String },
}

#[derive(Debug, Clone)]
pub(crate) struct VulnerabilityVersionInfo {
    pub purl: Purl,
    pub vulnerabilities: Vec<VulnerabilityInformation>,
}

impl VulnerabilityVersionInfo {
    pub fn find_highest_severity_vulnerability(
        vulnerabilities: &[VulnerabilityInformation],
    ) -> Option<&VulnerabilityInformation> {
        vulnerabilities
            .iter()
            .max_by(|a, b| b.severity.cmp(&a.severity))
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Ord, PartialEq, PartialOrd, Eq)]
pub(crate) enum Severity {
    Critical,
    High,
    Medium,
    Low,
    None,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct VulnerabilityInformation {
    pub severity: Severity,
    pub summary: String,
    pub detail: String,
    pub license: Vec<License>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct License {
    pub title: String,
    pub description: String,
}

#[async_trait]
pub(crate) trait VulnerabilityServer: Send + Sync {
    #[allow(dead_code)]
    // TODO: This will be required when we add back the completion task
    async fn get_versions_for_purl(&self, purl: Purl) -> anyhow::Result<Vec<Purl>>;

    async fn get_component_information(
        &self,
        purls: &[Purl],
    ) -> anyhow::Result<Vec<VulnerabilityVersionInfo>>;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_find_highest_severity_vulnerability() {
        let test = vec![
            VulnerabilityInformation {
                severity: Severity::Low,
                summary: "Low".to_string(),
                detail: "".to_string(),
                license: vec![],
            },
            VulnerabilityInformation {
                severity: Severity::Critical,
                summary: "Critical".to_string(),
                detail: "".to_string(),
                license: vec![],
            },
        ];
        let actual = VulnerabilityVersionInfo::find_highest_severity_vulnerability(&test);

        assert_eq!(actual.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_find_highest_severity_vulnerability_when_matching() {
        let test = vec![
            VulnerabilityInformation {
                severity: Severity::Critical,
                summary: "1".to_string(),
                detail: "".to_string(),
                license: vec![],
            },
            VulnerabilityInformation {
                severity: Severity::Critical,
                summary: "2".to_string(),
                detail: "".to_string(),
                license: vec![],
            },
        ];
        let actual = VulnerabilityVersionInfo::find_highest_severity_vulnerability(&test);

        assert_eq!(actual.unwrap().severity, Severity::Critical);
        assert_eq!(actual.unwrap().summary, "2".to_string());
    }
}
