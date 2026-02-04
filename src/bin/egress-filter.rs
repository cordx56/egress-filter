use anyhow::{Context, Result};
use clap::Parser;
use egress_filter::{AllowListConfig, Supervisor};
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Egress filter for running commands with network access control.
///
/// Intercepts network syscalls using seccomp and filters connections
/// based on an allow list configuration.
#[derive(Parser, Debug)]
#[command(name = "egress-filter")]
#[command(version, about)]
struct Args {
    /// Path to the allow list configuration file (YAML).
    /// If not specified, `egress-allowlist.yaml` in the current directory is used.
    #[arg(short = 'c', long)]
    config: Option<PathBuf>,

    /// Allow all connections (no filtering).
    #[arg(long, conflicts_with = "config")]
    allow_all: bool,

    /// Port for the DNS proxy server (0 = auto-assign).
    #[arg(short = 'p', long)]
    dns_proxy_port: Option<u16>,

    /// Command to run with egress filtering.
    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<String>,
}

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    let args = Args::parse();

    // Load or create allow list config
    let mut supervisor = if args.allow_all {
        let config = AllowListConfig::allow_all();
        Supervisor::new(config)
    } else {
        let config_path = args
            .config
            .unwrap_or_else(|| "egress-allowlist.yaml".into());
        let config = AllowListConfig::load(&config_path)
            .with_context(|| format!("failed to load config from {:?}", config_path))?;
        // Use with_config_path to enable hot-reloading
        Supervisor::with_config_path(config, config_path)
    };

    if let Some(port) = args.dns_proxy_port {
        supervisor = supervisor.with_dns_proxy_port(port);
    }

    // Run the command
    let exit_code = supervisor.run(&args.command)?;

    std::process::exit(exit_code);
}
