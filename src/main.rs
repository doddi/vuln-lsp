use std::{fs::File, sync::Mutex};

use clap::Parser;
use tracing::{info, trace};
use vuln_lsp::server;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[clap(short, long, default_value = "oss-index")]
    server: ServerType,

    /// The base url of a Nexus Lifecycle server, only used when using `Sonatype` server
    #[clap(short, long)]
    base_url: Option<String>,

    #[clap(short, long)]
    log_level: Option<LogLevel>,
    #[clap(short = 'f', long, default_value = "/tmp/trace.log")]
    log_file: String,
}

#[derive(Default, Clone, clap::ValueEnum, Debug)]
enum ServerType {
    Dummy,
    #[default]
    OssIndex,
    Sonatype,
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

    trace!("Starting Vuln Lsp");
    if let Some(level) = args.log_level {
        let log_file = File::create(args.log_file).expect("should create trace file");
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

    let server_type = match args.server {
        ServerType::Dummy => server::VulnerableServerType::Dummy,
        ServerType::OssIndex => server::VulnerableServerType::OssIndex,
        ServerType::Sonatype => match args.base_url {
            Some(base_url) => server::VulnerableServerType::Sonatype { base_url },
            _ => panic!(
                "both base_url and application must be specified for the sonatype server type"
            ),
        },
    };
    info!("Starting vuln-lsp connecting to: {:?}", server_type);
    vuln_lsp::start(server_type).await;
}
