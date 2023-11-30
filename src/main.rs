use std::{fs::File, sync::Mutex};
use vuln_lsp::server::VulnerableServerType;

use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[clap(default_value = "dummy")]
    server: ArgsServerType,
    #[clap(short, long)]
    log_level: Option<LogLevel>,
}

#[derive(Clone, clap::ValueEnum, Debug)]
enum ArgsServerType {
    Dummy,
    OssIndex,
}

impl From<ArgsServerType> for VulnerableServerType {
    fn from(val: ArgsServerType) -> Self {
        match val {
            ArgsServerType::Dummy => VulnerableServerType::Dummy,
            ArgsServerType::OssIndex => VulnerableServerType::OssIndex,
        }
    }
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

    info!("Starting vuln-lsp connecting to: {:?}", args.server);
    vuln_lsp::start(args.server.into()).await;
}
