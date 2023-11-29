use tower_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, CompletionResponse, Documentation, MarkupContent,
    MarkupKind,
};

use crate::server::{VulnerabilityInformationResponse, VulnerabilityVersionInfo};

impl From<VulnerabilityVersionInfo> for CompletionItem {
    fn from(value: VulnerabilityVersionInfo) -> Self {
        let markdown = build_markdown(&value);
        CompletionItem {
            label: value.version,
            kind: Some(CompletionItemKind::TEXT),
            detail: Some(value.information.summary),
            documentation: Some(markdown),
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
fn build_markdown(value: &VulnerabilityVersionInfo) -> Documentation {
    Documentation::MarkupContent(MarkupContent {
        kind: MarkupKind::Markdown,
        value: format_value(value),
    })
}

fn format_value(value: &VulnerabilityVersionInfo) -> String {
    [
        format!("# {}: {:?}\n\n", value.version, value.severity),
        "****".to_string(),
        format_summary(value),
        "****".to_string(),
        format_detail(value),
    ]
    .join("\n")
}

fn format_summary(value: &VulnerabilityVersionInfo) -> String {
    format!("## Summary\n\n{}\n\n", value.information.summary)
}

fn format_detail(value: &VulnerabilityVersionInfo) -> String {
    format!("## Detail\n\n{}\n\n", value.information.detail)
}

pub fn build_response(server_information: VulnerabilityInformationResponse) -> CompletionResponse {
    let versions = server_information
        .versions
        .into_iter()
        .map(|version| version.into())
        .collect();
    CompletionResponse::Array(versions)
}
