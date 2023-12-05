use tower_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, CompletionResponse, Documentation, MarkupContent,
    MarkupKind,
};

use crate::server::{Severity, VulnerabilityVersionInfo};

impl From<VulnerabilityVersionInfo> for CompletionItem {
    fn from(value: VulnerabilityVersionInfo) -> Self {
        let documentation = build_documentation(&value);
        let summary = build_summary(&value);
        CompletionItem {
            label: value.purl.version,
            kind: Some(CompletionItemKind::TEXT),
            detail: Some(summary),
            documentation: Some(documentation),
            deprecated: None,
            preselect: None,
            sort_text: None,
            filter_text: None,
            insert_text: None,
            insert_text_format: None,
            text_edit: None,
            additional_text_edits: None,
            commit_characters: None,
            command: None,
            data: None,
            tags: None,
            label_details: None,
            insert_text_mode: None,
        }
    }
}

fn build_summary(value: &VulnerabilityVersionInfo) -> String {
    value
        .vulnerabilities
        .iter()
        .fold("".to_string(), |acc, vulnerability| {
            format!("{acc}\n\n{}", vulnerability.summary)
        })
    // value
    //     .vulnerabilities
    //     .iter()
    //     .map(|vulnerability| format!("{}\n\n", vulnerability.summary))
    //     .collect()
}

fn build_documentation(value: &VulnerabilityVersionInfo) -> Documentation {
    Documentation::MarkupContent(MarkupContent {
        kind: MarkupKind::Markdown,
        value: format_value(value),
    })
}

fn format_value(value: &VulnerabilityVersionInfo) -> String {
    [
        format!(
            "{} has highest severity of {:?}\n\n",
            value.purl.version,
            highlight_severity(value)
        ),
        format_summary(value),
        format_detail(value),
    ]
    .join("\n")
}

fn highlight_severity(value: &VulnerabilityVersionInfo) -> Severity {
    value
        .vulnerabilities
        .iter()
        .map(|vulnerability| vulnerability.severity.clone())
        .max()
        .unwrap_or(Severity::None)
}

fn format_summary(value: &VulnerabilityVersionInfo) -> String {
    value
        .vulnerabilities
        .iter()
        .fold("".to_string(), |acc, vulnerability| {
            format!("{acc}\n\n{}", vulnerability.summary)
        })
}

fn format_detail(value: &VulnerabilityVersionInfo) -> String {
    value
        .vulnerabilities
        .iter()
        .fold("".to_string(), |acc, vulnerability| {
            format!("{acc}\n\n{}", vulnerability.detail)
        })
}

pub fn build_response(server_information: Vec<VulnerabilityVersionInfo>) -> CompletionResponse {
    let versions = server_information
        .into_iter()
        .map(|vulnerability| vulnerability.into())
        .collect();
    CompletionResponse::Array(versions)
}
