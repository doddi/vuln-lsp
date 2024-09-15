use std::{fs::File, sync::Mutex};

use super::LogLevel;

pub(super) fn create_file_tracer(log_level: LogLevel, log_file: String) {
    let log_file = File::create(log_file).expect("should create trace file");
    tracing_subscriber::fmt()
        .with_env_filter(format!("vuln_lsp={log_level:?}"))
        .with_writer(Mutex::new(log_file))
        .init();
}
