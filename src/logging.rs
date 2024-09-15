use std::{fs::File, sync::Mutex};

use opentelemetry::{global, KeyValue};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{HttpExporterBuilder, Protocol, WithExportConfig};
use opentelemetry_sdk::{logs, runtime, Resource};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use tracing_subscriber::prelude::*;

use crate::LogLevel;

pub fn enable_tracing_support(log_level: LogLevel, log_file: String) {
    // create_otlp_tracer(log_level);
    create_file_tracer(log_level, log_file);
}

// TODO: Get opentelemetry logging working
fn create_otlp_tracer(_log_level: LogLevel) {
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

fn create_file_tracer(log_level: LogLevel, log_file: String) {
    // let log_file = File::create(args.log_file).expect("should create trace file");
    let log_file = File::create(log_file).expect("should create trace file");
    tracing_subscriber::fmt()
        .with_env_filter(format!("vuln_lsp={log_level:?}"))
        .with_writer(Mutex::new(log_file))
        .init();
}
