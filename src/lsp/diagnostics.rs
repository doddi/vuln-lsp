use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity};

use crate::{
    server::{self, VulnerabilityInformationResponse},
    RangedPurl,
};

impl From<server::Severity> for Option<DiagnosticSeverity> {
    fn from(value: server::Severity) -> Self {
        match value {
            server::Severity::High => Some(DiagnosticSeverity::ERROR),
            server::Severity::Medium => Some(DiagnosticSeverity::WARNING),
            server::Severity::Low => Some(DiagnosticSeverity::INFORMATION),
            server::Severity::None => None,
        }
    }
}

pub fn calculate_diagnostics_for_vulnerabilities(
    ranged_purls: Vec<RangedPurl>,
    vulnerabilities: Vec<VulnerabilityInformationResponse>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for vulnerability in vulnerabilities {
        for ranged_purl in &ranged_purls {
            if ranged_purl.purl.version == vulnerability.purl.version
                && ranged_purl.purl.group_id == vulnerability.purl.group_id
                && ranged_purl.purl.artifact_id == vulnerability.purl.artifact_id
            {
                let version_info = &vulnerability.versions[0];
                let diagnostic = Diagnostic {
                    range: tower_lsp::lsp_types::Range {
                        start: tower_lsp::lsp_types::Position {
                            line: ranged_purl.range.start as u32,
                            character: 0,
                        },
                        end: tower_lsp::lsp_types::Position {
                            line: ranged_purl.range.end as u32,
                            character: 0,
                        },
                    },
                    severity: version_info.severity.into(),
                    code: None,
                    code_description: None,
                    source: Some("vulnerability".to_string()),
                    message: version_info.information.summary.clone(),
                    related_information: None,
                    tags: None,
                    data: None,
                };
                diagnostics.push(diagnostic);
            }
        }
    }
    diagnostics
}
