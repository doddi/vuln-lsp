use std::collections::HashMap;

use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity};
use tracing::trace;

use crate::server::{self, VulnerabilityVersionInfo};

use super::document_store::{MetadataDependencies, PurlRange};

impl From<server::Severity> for Option<DiagnosticSeverity> {
    fn from(value: server::Severity) -> Self {
        match value {
            server::Severity::Critical => Some(DiagnosticSeverity::ERROR),
            server::Severity::High => Some(DiagnosticSeverity::ERROR),
            server::Severity::Medium => Some(DiagnosticSeverity::WARNING),
            server::Severity::Low => Some(DiagnosticSeverity::INFORMATION),
            server::Severity::None => None,
        }
    }
}

pub fn calculate_diagnostics_for_vulnerabilities(
    dependencies: &MetadataDependencies,
    vulnerabilities: Vec<&VulnerabilityVersionInfo>,
) -> Vec<Diagnostic> {
    trace!("Matching up purls: {:?}", dependencies);
    trace!("Against: {:?}", vulnerabilities);

    let vulns: HashMap<PurlRange, Vec<&VulnerabilityVersionInfo>> = HashMap::new();
    for possible_vulnerability_match in vulnerabilities {
        dependencies.iter().for_each(|item| {
            if item.1.iter().any(|purl| {
                if purl.version == possible_vulnerability_match.purl.version
                    && purl.group_id == possible_vulnerability_match.purl.group_id
                    && purl.artifact_id == possible_vulnerability_match.purl.artifact_id
                {
                    return true;
                }
                else {
                    return false;
                }
            }) {
                // This vulnerability is brought in by this dependency
                if !vulns.contains_key(&item.0) {
                    vulns.insert(item.0.clone(), vec![]);    
                }
                let vulns_list = vulns.get(&item.0).expect("should always have an entry");
                vulns_list.push(possible_vulnerability_match)
            }
        });
    }


    let diagnostics = vulns.into_iter()
        .map(|vuln| {
            let highest_vulnerability = find_highest_severity_vulnerability_from_all(vuln.1).expect("at this point there should always be a vulnerability for the purl");
            Diagnostic {
                range: tower_lsp::lsp_types::Range {
                    start: tower_lsp::lsp_types::Position {
                        line: vuln.0.range.start.row as u32,
                        character: vuln.0.range.start.col as u32,
                    },
                    end: tower_lsp::lsp_types::Position {
                        line: vuln.0.range.end.row as u32,
                        character: vuln.0.range.end.col as u32,
                    },
                },
                severity: highest_vulnerability.severity.clone().into(),
                code: None,
                code_description: None,
                source: Some("vulnerability".to_string()),
                message: highest_vulnerability.summary.clone(),
                related_information: None,
                tags: None,
                data: None,
            }
        }).collect();
    diagnostics
}

fn find_highest_severity_vulnerability_from_all(
    vulnerabilities: Vec<&VulnerabilityVersionInfo>
) -> Option<&server::Information> {
    let highest = vulnerabilities.into_iter()
        .map(|vulnerability_info| find_highest_severity_vulnerability(&vulnerability_info.vulnerabilities).expect("always at least one vulnerability present"))
        .collect();
    find_highest_severity_vulnerability(highest)
}

fn find_highest_severity_vulnerability(
    vulnerabilities: &[server::Information],
) -> Option<&server::Information> {
    vulnerabilities
        .iter()
        .max_by(|a, b| a.severity.cmp(&b.severity))
}
