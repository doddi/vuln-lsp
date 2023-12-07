use std::{fs::File, sync::Mutex};

use clap::Parser;
use tracing::info;
use vuln_lsp::server;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[clap(default_value = "dummy")]
    server: String,

    #[clap(short, long)]
    base_url: Option<String>,
    #[clap(short, long)]
    application: Option<String>,

    #[clap(short, long)]
    log_level: Option<LogLevel>,
}

#[derive(Clone, clap::ValueEnum, Debug)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Some(level) = args.log_level {
        let log_file = File::create("/tmp/trace.log").expect("should create trace file");
        tracing_subscriber::fmt()
            .with_env_filter(format!("vuln_lsp={level:?}"))
            .with_writer(Mutex::new(log_file))
            .init();
        info!(
            "{} has tracing is enabled at level: {:?}",
            clap::crate_name!(),
            level
        );
    };

    let server_type = match args.server.as_str() {
        "dummy" => server::VulnerableServerType::Dummy,
        "oss-index" => server::VulnerableServerType::OssIndex,
        "sonatype" => match (args.base_url, args.application) {
            (Some(base_url), Some(application)) => {
                server::VulnerableServerType::Sonatype(base_url, application)
            }
            _ => panic!(
                "both base_url and application must be specified for the sonatype server type"
            ),
        },
        _ => panic!("Unknown server specified"),
    };
    info!("Starting vuln-lsp connecting to: {:?}", server_type);
    vuln_lsp::start(server_type).await;
}
