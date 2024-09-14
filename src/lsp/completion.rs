use serde_json::Value;
use tower_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, CompletionResponse, Documentation, MarkupContent,
    MarkupKind,
};
use tracing::debug;

use crate::{
    common::purl::Purl,
    server::{Severity, VulnerabilityVersionInfo},
};

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

impl From<Purl> for CompletionItem {
    fn from(value: Purl) -> Self {
        let purl = format!("{}", value);
        CompletionItem {
            label: value.version,
            kind: Some(CompletionItemKind::TEXT),
            detail: None,
            documentation: None,
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
            data: Some(Value::String(purl)),
            tags: None,
            label_details: None,
            insert_text_mode: None,
        }
    }
}

pub fn build_initial_response(purls: Vec<Purl>) -> CompletionResponse {
    let completion_response = purls
        .into_iter()
        .map(|purl| purl.into())
        .collect::<Vec<CompletionItem>>();
    debug!("initial completion response: {:?}", completion_response);
    CompletionResponse::Array(completion_response)
}

pub fn build_response(server_information: &VulnerabilityVersionInfo) -> CompletionItem {
    debug!("completion response: {:?}", server_information);
    (*server_information).clone().into()
}
