use crate::server::VulnerabilityVersionInfo;
use tower_lsp::lsp_types::{HoverContents, MarkupContent, MarkupKind::Markdown};

pub(crate) fn create_hover_message(
    component_info: Vec<VulnerabilityVersionInfo>,
) -> Option<HoverContents> {
    if !component_info.is_empty() {
        if let Some(vulnerability) = component_info[0]
            .find_highest_severity_vulnerability(&component_info[0].vulnerabilities)
        {
            return Some(HoverContents::Markup(MarkupContent {
                kind: Markdown,
                value: format!(
                    r#"{}
                Severity: {:?}
                {}
                {}
                "#,
                    component_info[0].purl,
                    vulnerability.severity,
                    vulnerability.summary,
                    vulnerability.detail,
                ),
            }));
        }
    }
    None
}
