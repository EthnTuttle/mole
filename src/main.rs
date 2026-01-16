//! Mole - Secure SSH tunneling over Iroh
//!
//! Mole creates encrypted peer-to-peer tunnels to access SSH on remote machines
//! without exposing ports to the public internet. All connections are:
//! - End-to-end encrypted using QUIC/TLS
//! - Authenticated using Ed25519 public keys
//! - Direct when possible, relayed when necessary

mod protocol;
mod security;
mod server;
mod client;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser)]
#[command(name = "mole")]
#[command(about = "Secure SSH tunneling over Iroh - access your machine from anywhere")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as a server on the host machine (accepts SSH tunnel connections)
    Serve {
        /// SSH server address to tunnel to (default: 127.0.0.1:22)
        #[arg(short, long, default_value = "127.0.0.1:22")]
        ssh_addr: String,

        /// Path to authorized keys file (node IDs that can connect)
        #[arg(short, long)]
        authorized_keys: Option<String>,

        /// Generate and display a connection ticket, then exit
        #[arg(long)]
        ticket: bool,
    },

    /// Connect to a remote mole server and start SSH tunnel
    Connect {
        /// Connection ticket from the server
        ticket: String,

        /// Local port to listen on for SSH connections
        #[arg(short, long, default_value = "2222")]
        local_port: u16,
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("mole=debug,iroh=debug")
    } else {
        EnvFilter::new("mole=info,iroh=warn")
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    match cli.command {
        Commands::Serve {
            ssh_addr,
            authorized_keys,
            ticket,
        } => {
            server::run(ssh_addr, authorized_keys, ticket).await?;
        }

        Commands::Connect { ticket, local_port } => {
            client::run(ticket, local_port).await?;
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
                security::generate_identity().await?;
            }
        },

        Commands::Info => {
            show_info().await?;
        }
    }

    Ok(())
}

async fn show_info() -> Result<()> {
    use iroh::Endpoint;

    let endpoint = Endpoint::bind().await?;
    let node_id = endpoint.node_id();

    println!("Mole Node Information");
    println!("=====================");
    println!("Node ID: {}", node_id);
    println!();
    println!("Share this Node ID with servers to get authorized access.");
    println!();
    println!("Config directory: {}", security::config_dir()?.display());

    endpoint.close().await;
    Ok(())
}
