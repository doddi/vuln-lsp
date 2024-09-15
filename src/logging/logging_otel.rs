use opentelemetry::KeyValue;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{HttpExporterBuilder, Protocol, WithExportConfig};
use opentelemetry_sdk::{runtime, Resource};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use tracing_subscriber::prelude::*;

use super::LogLevel;

// TODO: Get opentelemetry logging working
pub(super) fn create_otlp_tracer(_log_level: LogLevel) {
    let resource = Resource::new(vec![KeyValue::new(SERVICE_NAME, "vuln-lsp")]);

    let log_provider = opentelemetry_otlp::new_pipeline()
        .logging()
        .with_resource(resource)
        .with_exporter(http_exporter().with_protocol(Protocol::HttpBinary))
        .install_batch(runtime::Tokio)
        .expect("opentelemetry log provider");

    let layer = OpenTelemetryTracingBridge::new(&log_provider);

    tracing_subscriber::registry().with(layer).init();
}

fn http_exporter() -> HttpExporterBuilder {
    opentelemetry_otlp::new_exporter().http()
}
