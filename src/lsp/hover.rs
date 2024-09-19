use crate::{common::purl::Purl, server::VulnerabilityInformation};
use tower_lsp::lsp_types::{HoverContents, MarkupContent, MarkupKind::Markdown};

pub(crate) fn create_hover_message(
    direct: &Purl,
    transitive: Option<Purl>,
    component_info: VulnerabilityInformation,
) -> HoverContents {
    if let Some(transitive) = transitive {
        HoverContents::Markup(MarkupContent {
            kind: Markdown,
            value: format!(
                r#"Direct: {}
                brings in: {}
                Severity: {:?}
                {}
                {}
                "#,
                direct,
                transitive,
                component_info.severity,
                component_info.summary,
                component_info.detail,
            ),
        })
    } else {
        HoverContents::Markup(MarkupContent {
            kind: Markdown,
            value: format!(
                r#"Direct: {}
                Severity: {:?}
                {}
                {}
                "#,
                direct, component_info.severity, component_info.summary, component_info.detail,
            ),
        })
    }
}
