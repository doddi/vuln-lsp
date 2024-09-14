use std::{fs::File, sync::Mutex};

use opentelemetry::KeyValue;
use opentelemetry_sdk::{trace::Config, Resource};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::LogLevel;

pub fn enable_tracing_support(log_level: LogLevel) {
    // create_otlp_tracer();
    create_file_tracer(log_level);
}

// TODO: Get opentelemetry logging working
fn create_otlp_tracer(log_level: LogLevel) {
    let tracer = opentelemetry_otlp::new_pipeline().tracing();
    let exporter = opentelemetry_otlp::new_exporter().http();

    let kv = KeyValue::new("service.name", "vuln-lsp");
    let kvs = vec![kv];
    let resource = Resource::new(kvs);
    let tracer_provider = tracer
        .with_trace_config(Config::default().with_resource(resource))
        .with_exporter(exporter)
        .install_simple()
        .unwrap();

    opentelemetry::global::set_tracer_provider(tracer_provider);

    let fmt_layer = tracing_subscriber::fmt::layer();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(format!(
            "vuln_lsp={log_level:?}"
        )))
        .with(fmt_layer)
        // .with(telemetry_layer)
        .init();
}

fn create_file_tracer(log_level: LogLevel) {
    // let log_file = File::create(args.log_file).expect("should create trace file");
    let log_file = File::create("/tmp/vuln-lsp.log").expect("should create trace file");
    tracing_subscriber::fmt()
        .with_env_filter(format!("vuln_lsp={log_level:?}"))
        .with_writer(Mutex::new(log_file))
        .init();
}
