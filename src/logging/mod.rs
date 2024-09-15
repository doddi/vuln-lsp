#[cfg(feature = "logging-file")]
mod logging_file;
#[cfg(feature = "logging-otel")]
mod logging_otel;

#[derive(Clone, clap::ValueEnum, Debug)]
pub(crate) enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

pub fn enable_tracing(log_level: LogLevel, logging_file: String) {
    #[cfg(feature = "logging-file")]
    logging_file::create_file_tracer(log_level, logging_file);
    #[cfg(feature = "logging-otel")]
    logging_otel::create_otlp_tracer(log_level);
}
