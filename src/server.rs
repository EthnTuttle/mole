//! Server module for Mole
//!
//! The server runs on the host machine that you want to access remotely.
//! It accepts incoming Iroh connections from authorized clients and tunnels
//! them to the local SSH server.

use anyhow::{Context, Result};
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh_tickets::{endpoint::EndpointTicket, Ticket};
use tracing::{info, warn};

use crate::protocol::{SshTunnelProtocol, ALPN};
use crate::security::AuthorizedKeys;

/// Run the mole server
pub async fn run(
    ssh_addr: String,
    authorized_keys_path: Option<String>,
    ticket_only: bool,
) -> Result<()> {
    // Load authorized keys
    let authorized_keys = if let Some(path) = authorized_keys_path {
        AuthorizedKeys::from_file(&path)?
    } else {
        AuthorizedKeys::from_default_config()?
    };

    // Create the endpoint with our ALPN
    let endpoint = Endpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .context("Failed to create Iroh endpoint")?;

    // Wait for the endpoint to be reachable
    info!("Waiting for endpoint to come online...");
    endpoint.online().await;

    let node_id = endpoint.node_id();
    info!("Server node ID: {}", node_id);

    // Generate the connection ticket
    let addr = endpoint.addr().await?;
    let ticket = EndpointTicket::new(addr);
    let ticket_str = ticket.serialize();

    if ticket_only {
        // Just print the ticket and exit
        println!("{}", ticket_str);
        endpoint.close().await;
        return Ok(());
    }

    // Print connection information
    println!();
    println!("========================================");
    println!("  Mole SSH Tunnel Server");
    println!("========================================");
    println!();
    println!("Node ID: {}", node_id);
    println!("SSH Target: {}", ssh_addr);
    println!();
    println!("Connection Ticket (share with clients):");
    println!();
    println!("{}", ticket_str);
    println!();
    println!("========================================");
    println!();
    println!("Clients can connect with:");
    println!("  mole connect {}", ticket_str);
    println!();
    println!("Waiting for connections... (Ctrl+C to stop)");
    println!();

    // Create the protocol handler
    let protocol = SshTunnelProtocol::new(ssh_addr, authorized_keys);

    // Build and spawn the router
    let router = Router::builder(endpoint)
        .accept(ALPN, protocol)
        .spawn();

    // Wait for shutdown signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    // Graceful shutdown
    info!("Shutting down server...");
    router.shutdown().await?;

    Ok(())
}
