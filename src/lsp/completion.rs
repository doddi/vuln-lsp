use tower_lsp::lsp_types::{CompletionItem, CompletionItemKind, CompletionResponse, Documentation};

use crate::vulnerability_server::{VulnerabilityInformationResponse, VulnerabilityVersionInfo};

impl From<VulnerabilityVersionInfo> for CompletionItem {
    fn from(value: VulnerabilityVersionInfo) -> Self {
        CompletionItem {
            label: value.version,
            kind: Some(CompletionItemKind::TEXT),
            detail: Some(value.information.detail),
            documentation: Some(Documentation::String(value.information.summary)),
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

pub fn build_response(server_information: VulnerabilityInformationResponse) -> CompletionResponse {
    let versions = server_information
        .versions
        .into_iter()
        .map(|version| version.into())
        .collect();
    CompletionResponse::Array(versions)
}