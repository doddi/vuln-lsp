use std::collections::{hash_map::Entry, HashMap};

use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity};
use tracing::trace;

use crate::{
    common::purl_range::PurlRange,
    parsers::ParseContent,
    server::{self, VulnerabilityVersionInfo},
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

pub fn calculate_diagnostics_for_vulnerabilities(
    parsed_content: ParseContent,
    vulnerabilities: Vec<&VulnerabilityVersionInfo>,
) -> Vec<Diagnostic> {
    let mut vulns: HashMap<PurlRange, Vec<&VulnerabilityVersionInfo>> = HashMap::new();

    for possible_vulnerability_match in vulnerabilities {
        // Find the direct dependency purl range that matched up to this vulnerability
        for (direct, transitives) in &parsed_content.transitives {
            // Transitives should always include the direct dependency too incase the vulnerability
            // is associated with that.
            // TODO: Look at the direct dependency list first so it can be flagged as a direct
            if transitives.contains(&possible_vulnerability_match.purl) {
                // Get the purl range that the transitive is linked to
                if let Some(range) = parsed_content.ranges.get(direct) {
                    let purl_range = PurlRange {
                        purl: direct.clone(),
                        range: range.clone(),
                    };

                    if let Entry::Vacant(entry) = vulns.entry(purl_range.clone()) {
                        entry.insert(vec![possible_vulnerability_match]);
                    } else if let Some(list) = vulns.get_mut(&purl_range) {
                        list.push(possible_vulnerability_match);
                    }
                }
            }
        }
    }

    trace!("Vulnerabilities matched: {:?}", vulns);
    let diagnostics = build_diagnostics(vulns);

    trace!("Diagnostics: {:?}", diagnostics);
    diagnostics
}

fn build_diagnostics(vulns: HashMap<PurlRange, Vec<&VulnerabilityVersionInfo>>) -> Vec<Diagnostic> {
    let diagnostics = vulns
        .into_iter()
        .map(|(purl_range, vuln)| {
            let highest_vulnerability = find_highest_severity_vulnerability_from_all(
                vuln.iter().map(|&v| v.clone()).collect(),
            )
            .expect("at this point there should always be a vulnerability for the purl");

            Diagnostic {
                range: tower_lsp::lsp_types::Range {
                    start: tower_lsp::lsp_types::Position {
                        line: purl_range.range.start.row as u32,
                        character: purl_range.range.start.col as u32,
                    },
                    end: tower_lsp::lsp_types::Position {
                        line: purl_range.range.end.row as u32,
                        character: purl_range.range.end.col as u32,
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
        })
        .collect();
    diagnostics
}

fn find_highest_severity_vulnerability_from_all(
    vulnerabilities: Vec<VulnerabilityVersionInfo>,
) -> Option<server::VulnerabilityInformation> {
    let highest: Vec<server::VulnerabilityInformation> = vulnerabilities
        .iter()
        .filter(|vulnerability_info| !vulnerability_info.vulnerabilities.is_empty())
        .map(|vulnerability_info| {
            // trace!("Finding highest severity vulnerability from all: {:?}", vulnerability_info.vulnerabilities.clone());

            find_highest_severity_vulnerability(vulnerability_info.vulnerabilities.clone())
                .expect("always at least one vulnerability present")
        })
        .collect();
    find_highest_severity_vulnerability(highest)
}

fn find_highest_severity_vulnerability(
    vulnerabilities: Vec<server::VulnerabilityInformation>,
) -> Option<server::VulnerabilityInformation> {
    let highest = vulnerabilities
        .iter()
        .max_by(|a, b| a.severity.cmp(&b.severity))
        .cloned();
    highest
}
