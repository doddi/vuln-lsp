use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity};
use tracing::trace;

use crate::server::{self, VulnerabilityVersionInfo};

use super::document_store::PurlRange;

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
    ranged_purls: Vec<PurlRange>,
    vulnerabilities: Vec<&VulnerabilityVersionInfo>,
) -> Vec<Diagnostic> {
    trace!("Matching up purls: {:?}", ranged_purls);
    trace!("Against: {:?}", vulnerabilities);

    let mut diagnostics = Vec::new();
    for possible_vulnerability_match in vulnerabilities {
        for ranged_purl in &ranged_purls {
            if ranged_purl.purl.version == possible_vulnerability_match.purl.version
                && ranged_purl.purl.group_id == possible_vulnerability_match.purl.group_id
                && ranged_purl.purl.artifact_id == possible_vulnerability_match.purl.artifact_id
            {
                let vulnerabilities_for_purl = &possible_vulnerability_match.vulnerabilities;
                if let Some(highest_vulnerability) =
                    find_highest_severity_vulnerability(vulnerabilities_for_purl)
                {
                    let diagnostic = Diagnostic {
                        range: tower_lsp::lsp_types::Range {
                            start: tower_lsp::lsp_types::Position {
                                line: ranged_purl.range.start.row as u32,
                                character: ranged_purl.range.start.col as u32,
                            },
                            end: tower_lsp::lsp_types::Position {
                                line: ranged_purl.range.end.row as u32,
                                character: ranged_purl.range.end.col as u32,
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
                    };
                    diagnostics.push(diagnostic);
                }
            }
        }
    }
    diagnostics
}

fn find_highest_severity_vulnerability(
    vulnerabilities: &[server::Information],
) -> Option<&server::Information> {
    vulnerabilities
        .iter()
        .max_by(|a, b| a.severity.cmp(&b.severity))
}
