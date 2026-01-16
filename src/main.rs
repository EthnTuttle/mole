//! Mole - Secure TCP tunneling over Iroh
//!
//! Mole creates encrypted peer-to-peer tunnels to access TCP services on remote
//! machines without exposing ports to the public internet. All connections are:
//! - End-to-end encrypted using QUIC/TLS
//! - Authenticated using Ed25519 public keys
//! - Direct when possible, relayed when necessary

mod client;
#[cfg(feature = "gui")]
mod gui;
mod protocol;
mod security;
mod server;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser)]
#[command(name = "mole")]
#[command(about = "Secure TCP tunneling over Iroh - access any service from anywhere")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch the graphical user interface
    #[cfg(feature = "gui")]
    Gui {
        /// Start in server or client mode
        #[arg(short, long, value_parser = ["server", "client"])]
        mode: Option<String>,
    },

    /// Run as a server on the host machine (accepts tunnel connections)
    Serve {
        /// Tunnel specifications: name:host:port[:local_port]
        /// Examples: ssh:127.0.0.1:22:2222, postgres:127.0.0.1:5432
        /// If no tunnels specified, defaults to ssh:127.0.0.1:22:2222
        #[arg(short, long = "tunnel", value_name = "SPEC")]
        tunnels: Vec<String>,

        /// Path to authorized keys file (node IDs that can connect)
        #[arg(short, long)]
        authorized_keys: Option<String>,

        /// Generate and display a connection ticket, then exit
        #[arg(long)]
        ticket: bool,
    },

    /// Connect to a remote mole server and start tunnels
    Connect {
        /// Connection ticket from the server
        ticket: String,

        /// Tunnel bindings: name:local_port (e.g., ssh:2222, postgres:5432)
        /// If not specified, uses defaults from common tunnel names
        #[arg(short, long = "tunnel", value_name = "BINDING")]
        tunnels: Vec<String>,
    },

    /// Manage authorized keys
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },

    /// Show information about this node
    Info,
}

#[derive(Subcommand)]
enum KeysAction {
    /// List all authorized keys
    List,

    /// Add a new authorized key (node ID)
    Add {
        /// Node ID to authorize
        node_id: String,

        /// Optional label for this key
        #[arg(short, long)]
        label: Option<String>,
    },

    /// Remove an authorized key
    Remove {
        /// Node ID to remove
        node_id: String,
    },

    /// Generate a new node identity and show its ID
    Generate,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // If no command specified, launch GUI (if available)
    #[cfg(feature = "gui")]
    if cli.command.is_none() {
        return gui::run_gui(None);
    }

    #[cfg(not(feature = "gui"))]
    if cli.command.is_none() {
        eprintln!("No command specified. Run with --help for usage.");
        std::process::exit(1);
    }

    // Initialize logging for CLI commands
    let filter = if cli.verbose {
        EnvFilter::new("mole=debug,iroh=debug")
    } else {
        EnvFilter::new("mole=info,iroh=warn")
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    // Build runtime for async commands
    let runtime = tokio::runtime::Runtime::new()?;

    match cli.command.unwrap() {
        #[cfg(feature = "gui")]
        Commands::Gui { mode } => {
            // Drop runtime before starting GUI (GUI creates its own)
            drop(runtime);
            gui::run_gui(mode.as_deref())?;
        }

        Commands::Serve {
            tunnels,
            authorized_keys,
            ticket,
        } => {
            runtime.block_on(server::run(tunnels, authorized_keys, ticket))?;
        }

        Commands::Connect { ticket, tunnels } => {
            let bindings = parse_tunnel_bindings(&tunnels)?;
            runtime.block_on(client::run(ticket, bindings))?;
        }

        Commands::Keys { action } => match action {
            KeysAction::List => {
                security::list_authorized_keys()?;
            }
            KeysAction::Add { node_id, label } => {
                security::add_authorized_key(&node_id, label.as_deref())?;
            }
            KeysAction::Remove { node_id } => {
                security::remove_authorized_key(&node_id)?;
            }
            KeysAction::Generate => {
                runtime.block_on(security::generate_identity())?;
            }
        },

        Commands::Info => {
            runtime.block_on(show_info())?;
        }
    }

    Ok(())
}

/// Parse tunnel bindings from command line
/// Format: name:local_port or just name (uses default port)
fn parse_tunnel_bindings(specs: &[String]) -> Result<Vec<client::TunnelBinding>> {
    // If no specs provided, use default SSH binding
    if specs.is_empty() {
        return Ok(vec![client::TunnelBinding {
            name: "ssh".to_string(),
            local_port: 2222,
        }]);
    }

    let mut bindings = Vec::new();

    for spec in specs {
        let parts: Vec<&str> = spec.split(':').collect();

        let binding = match parts.len() {
            2 => client::TunnelBinding {
                name: parts[0].to_string(),
                local_port: parts[1]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid port in: {}", spec))?,
            },
            1 => {
                // Use default ports for known services
                let name = parts[0];
                let port = default_port_for_service(name);
                client::TunnelBinding {
                    name: name.to_string(),
                    local_port: port,
                }
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid tunnel binding: {}. Expected format: name:port or name",
                    spec
                ));
            }
        };

        bindings.push(binding);
    }

    Ok(bindings)
}

/// Get default local port for known service names
fn default_port_for_service(name: &str) -> u16 {
    match name.to_lowercase().as_str() {
        "ssh" => 2222,
        "postgres" | "postgresql" => 5432,
        "mysql" | "mariadb" => 3306,
        "redis" => 6379,
        "mongodb" | "mongo" => 27017,
        "http" | "web" => 8080,
        "https" => 8443,
        "vnc" => 5900,
        "rdp" => 3389,
        _ => 9000, // Default fallback
    }
}

async fn show_info() -> Result<()> {
    use iroh::Endpoint;

    let endpoint = Endpoint::bind().await?;
    let endpoint_id = endpoint.id();

    println!("Mole Endpoint Information");
    println!("=========================");
    println!("Endpoint ID: {}", endpoint_id);
    println!();
    println!("Share this Endpoint ID with servers to get authorized access.");
    println!();
    println!("Config directory: {}", security::config_dir()?.display());

    endpoint.close().await;
    Ok(())
}
