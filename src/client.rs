//! Client module for Mole
//!
//! The client runs on your local development machine. It connects to a
//! remote mole server and creates a local TCP listener that tunnels
//! connections through Iroh to the remote SSH server.

use anyhow::{anyhow, Context, Result};
use iroh::Endpoint;
use iroh_tickets::{endpoint::EndpointTicket, Ticket};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use crate::protocol::ALPN;

/// Run the mole client
pub async fn run(ticket_str: String, local_port: u16) -> Result<()> {
    // Parse the connection ticket
    let ticket = EndpointTicket::deserialize(&ticket_str)
        .map_err(|e| anyhow!("Invalid connection ticket: {}", e))?;

    let remote_addr = ticket.endpoint_addr().clone();
    let remote_node_id = remote_addr.node_id;

    info!("Connecting to remote server: {}", remote_node_id);

    // Create our endpoint
    let endpoint = Endpoint::bind()
        .await
        .context("Failed to create Iroh endpoint")?;

    let our_node_id = endpoint.node_id();
    info!("Our node ID: {}", our_node_id);

    // Connect to the remote server
    info!("Establishing connection...");
    let connection = endpoint
        .connect(remote_addr, ALPN)
        .await
        .context("Failed to connect to remote server")?;

    info!("Connected to remote server!");

    // Wrap connection in Arc for sharing across tasks
    let connection = Arc::new(connection);

    // Start local TCP listener
    let bind_addr = format!("127.0.0.1:{}", local_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind to {}", bind_addr))?;

    println!();
    println!("========================================");
    println!("  Mole SSH Tunnel Client");
    println!("========================================");
    println!();
    println!("Connected to: {}", remote_node_id);
    println!("Local tunnel: 127.0.0.1:{}", local_port);
    println!();
    println!("Connect to the remote machine with:");
    println!("  ssh -p {} localhost", local_port);
    println!();
    println!("Or configure your SSH config:");
    println!("  Host my-remote-dev");
    println!("      HostName localhost");
    println!("      Port {}", local_port);
    println!("      User your-username");
    println!();
    println!("Tunnel active... (Ctrl+C to stop)");
    println!();

    // Accept local TCP connections and tunnel them
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((tcp_stream, peer_addr)) => {
                        info!("New local connection from {}", peer_addr);

                        let connection = connection.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_local_connection(tcp_stream, connection).await {
                                debug!("Tunnel session ended: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept local connection: {}", e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal");
                break;
            }
        }
    }

    // Graceful shutdown
    info!("Closing connection...");
    connection.close(0u32.into(), b"client shutdown");
    endpoint.close().await;

    Ok(())
}

/// Handle a local TCP connection by tunneling it through Iroh
async fn handle_local_connection(
    tcp_stream: TcpStream,
    connection: Arc<iroh::endpoint::Connection>,
) -> Result<()> {
    // Open a new bidirectional stream on the Iroh connection
    let (mut iroh_send, mut iroh_recv) = connection
        .open_bi()
        .await
        .context("Failed to open tunnel stream")?;

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // Bidirectionally copy data between local TCP and Iroh stream
    let copy_to_remote = async {
        tokio::io::copy(&mut tcp_read, &mut iroh_send).await
    };

    let copy_from_remote = async {
        tokio::io::copy(&mut iroh_recv, &mut tcp_write).await
    };

    // Run both directions concurrently
    tokio::select! {
        result = copy_to_remote => {
            match result {
                Ok(bytes) => debug!("Sent {} bytes to remote", bytes),
                Err(e) => debug!("Send to remote ended: {}", e),
            }
        }
        result = copy_from_remote => {
            match result {
                Ok(bytes) => debug!("Received {} bytes from remote", bytes),
                Err(e) => debug!("Receive from remote ended: {}", e),
            }
        }
    }

    // Signal end of stream
    let _ = iroh_send.finish();

    debug!("Tunnel session completed");
    Ok(())
}
