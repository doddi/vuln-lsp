use std::fmt::Debug;

mod logging;

use clap::{ArgAction, Parser};
use logging::{enable_tracing, LogLevel};
use tracing::info;
use vuln_lsp::server;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[clap(short, long, default_value = "oss-index")]
    server: ServerType,

    #[clap(short, long, action=ArgAction::SetFalse)]
    direct_only: bool,

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

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Some(log_level) = args.log_level {
        enable_tracing(log_level, args.log_file);
    }
    info!("Starting Vuln Lsp");

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
    info!(
        "Starting vuln-lsp connecting to: {:?} direct parsing: {}",
        server_type, args.direct_only
    );
    vuln_lsp::start(server_type, args.direct_only).await;
}
