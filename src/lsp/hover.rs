use crate::{common::purl::Purl, server::VulnerabilityInformation};
use tower_lsp::lsp_types::{HoverContents, MarkupContent, MarkupKind::Markdown};

pub(crate) fn create_hover_message(
    direct: &Purl,
    transitive: Option<Purl>,
    component_info: VulnerabilityInformation,
) -> HoverContents {
    HoverContents::Markup(MarkupContent {
        kind: Markdown,
        value: format!(
            r#"Direct: {}
            {}
                Severity: {:?}
                {}
                {}
                "#,
            direct,
            if transitive.is_some() {
                format!("brings in {}", transitive.unwrap())
            } else {
                String::new()
            },
            component_info.severity,
            component_info.summary,
            component_info.detail,
        ),
    })
}
