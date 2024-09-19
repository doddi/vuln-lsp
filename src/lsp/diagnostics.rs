use tower_lsp::lsp_types::{self, Diagnostic, DiagnosticSeverity};

use crate::{
    common::purl_range::PurlRange,
    server::{self, VulnerabilityInformation},
};

impl From<server::Severity> for Option<DiagnosticSeverity> {
    fn from(value: server::Severity) -> Self {
        match value {
            server::Severity::Critical => Some(DiagnosticSeverity::ERROR),
            server::Severity::High => Some(DiagnosticSeverity::WARNING),
            server::Severity::Medium => Some(DiagnosticSeverity::WARNING),
            server::Severity::Low => Some(DiagnosticSeverity::INFORMATION),
            server::Severity::None => None,
        }
    }
}

pub(crate) fn create_diagnostic(
    purl_range: &PurlRange,
    version_information: &VulnerabilityInformation,
) -> Diagnostic {
    Diagnostic {
        range: lsp_types::Range {
            start: lsp_types::Position {
                line: purl_range.range.start.row as u32,
                character: purl_range.range.start.col as u32,
            },
            end: lsp_types::Position {
                line: purl_range.range.end.row as u32,
                character: purl_range.range.end.col as u32,
            },
        },
        severity: version_information.severity.clone().into(),
        code: None,
        code_description: None,
        source: Some("vulnerability".to_string()),
        message: version_information.summary.clone(),
        related_information: None,
        tags: None,
        data: None,
    }
}
