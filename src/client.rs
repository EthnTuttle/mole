//! Client module for Mole
//!
//! The client runs on your local development machine. It connects to a
//! remote mole server and creates local TCP listeners that tunnel
//! connections through Iroh to configured remote services.

use anyhow::{anyhow, Context, Result};
use iroh::{Endpoint, EndpointAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

use crate::protocol::{read_tunnel_response, send_tunnel_request, TunnelRequest, ALPN};

/// Maximum concurrent connections per tunnel
const MAX_CONNECTIONS_PER_TUNNEL: usize = 100;

/// Tunnel binding configuration
#[derive(Debug, Clone)]
pub struct TunnelBinding {
    /// Name of the tunnel (must match server config)
    pub name: String,
    /// Local port to listen on
    pub local_port: u16,
}

/// Run the mole client
pub async fn run(addr_str: String, tunnel_bindings: Vec<TunnelBinding>) -> Result<()> {
    // Parse the endpoint address
    let remote_addr = EndpointAddr::from_str(&addr_str)
        .map_err(|e| anyhow!("Invalid endpoint address: {}", e))?;

    let remote_endpoint_id = remote_addr.node_id;

    info!("Connecting to remote server: {}", remote_endpoint_id);

    // Create our endpoint
    let endpoint = Endpoint::bind()
        .await
        .context("Failed to create Iroh endpoint")?;

    let our_endpoint_id = endpoint.id();
    info!("Our endpoint ID: {}", our_endpoint_id);

    // Connect to the remote server
    info!("Establishing connection...");
    let connection = endpoint
        .connect(remote_addr, ALPN)
        .await
        .context("Failed to connect to remote server")?;

    info!("Connected to remote server!");

    // Wrap connection in Arc for sharing across tasks
    let connection = Arc::new(connection);

    // Print connection information
    println!();
    println!("========================================");
    println!("  Mole TCP Tunnel Client");
    println!("========================================");
    println!();
    println!("Connected to:    {}", remote_endpoint_id);
    println!("Our Endpoint ID: {}", our_endpoint_id);
    println!();
    println!("Active Tunnels:");

    // Start listeners for each tunnel
    let mut handles = Vec::new();

    for binding in &tunnel_bindings {
        let bind_addr = format!("127.0.0.1:{}", binding.local_port);
        let listener = TcpListener::bind(&bind_addr)
            .await
            .with_context(|| format!("Failed to bind to {}", bind_addr))?;

        println!(
            "  {} -> localhost:{} (listening)",
            binding.name, binding.local_port
        );

        let connection = connection.clone();
        let tunnel_name = binding.name.clone();
        let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_TUNNEL));

        let handle = tokio::spawn(async move {
            run_tunnel_listener(listener, connection, tunnel_name, semaphore).await
        });

        handles.push(handle);
    }

    println!();
    println!("========================================");
    println!();
    println!("Example usage:");
    for binding in &tunnel_bindings {
        match binding.name.as_str() {
            "ssh" => println!("  ssh -p {} localhost", binding.local_port),
            "postgres" => println!(
                "  psql -h localhost -p {} -U postgres",
                binding.local_port
            ),
            "mysql" => println!("  mysql -h 127.0.0.1 -P {}", binding.local_port),
            "redis" => println!("  redis-cli -p {}", binding.local_port),
            "web" | "http" => println!("  curl http://localhost:{}", binding.local_port),
            _ => println!("  Connect to localhost:{} for {}", binding.local_port, binding.name),
        }
    }
    println!();
    println!("Tunnels active... (Ctrl+C to stop)");
    println!();

    // Wait for shutdown signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
        // Also exit if all listeners fail
        _ = async {
            for handle in &mut handles {
                let _ = handle.await;
            }
        } => {
            error!("All tunnel listeners exited");
        }
    }

    // Graceful shutdown
    info!("Closing connection...");
    connection.close(0u32.into(), b"client shutdown");
    endpoint.close().await;

    Ok(())
}

/// Run a listener for a single tunnel
async fn run_tunnel_listener(
    listener: TcpListener,
    connection: Arc<iroh::endpoint::Connection>,
    tunnel_name: String,
    semaphore: Arc<Semaphore>,
) -> Result<()> {
    loop {
        match listener.accept().await {
            Ok((tcp_stream, peer_addr)) => {
                info!(
                    "New connection from {} for tunnel {}",
                    peer_addr, tunnel_name
                );

                // Acquire semaphore permit to limit concurrent connections
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        error!(
                            "Too many connections for tunnel {}, rejecting",
                            tunnel_name
                        );
                        continue;
                    }
                };

                let connection = connection.clone();
                let tunnel_name = tunnel_name.clone();

                tokio::spawn(async move {
                    // Hold permit until connection completes
                    let _permit = permit;

                    if let Err(e) =
                        handle_local_connection(tcp_stream, connection, &tunnel_name).await
                    {
                        debug!("Tunnel session for {} ended: {}", tunnel_name, e);
                    }
                });
            }
            Err(e) => {
                error!(
                    "Failed to accept connection for tunnel {}: {}",
                    tunnel_name, e
                );
            }
        }
    }
}

/// Handle a local TCP connection by tunneling it through Iroh
async fn handle_local_connection(
    tcp_stream: TcpStream,
    connection: Arc<iroh::endpoint::Connection>,
    tunnel_name: &str,
) -> Result<()> {
    // Open a new bidirectional stream on the Iroh connection
    let (mut iroh_send, mut iroh_recv) = connection
        .open_bi()
        .await
        .context("Failed to open tunnel stream")?;

    // Send tunnel request
    let request = TunnelRequest {
        tunnel_name: tunnel_name.to_string(),
    };
    send_tunnel_request(&mut iroh_send, &request).await?;

    // Read response
    let response = read_tunnel_response(&mut iroh_recv).await?;

    if !response.accepted {
        let err_msg = response.error.unwrap_or_else(|| "Unknown error".to_string());
        return Err(anyhow!("Tunnel rejected: {}", err_msg));
    }

    debug!("Tunnel {} established", tunnel_name);

    // Now do bidirectional copy
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    let copy_to_remote = async { tokio::io::copy(&mut tcp_read, &mut iroh_send).await };

    let copy_from_remote = async { tokio::io::copy(&mut iroh_recv, &mut tcp_write).await };

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

    debug!("Tunnel session for {} completed", tunnel_name);
    Ok(())
}
