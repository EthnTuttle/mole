//! TCP Tunnel Protocol for Mole
//!
//! This module defines the protocol used for tunneling TCP connections over Iroh.
//! The protocol is designed with security as a primary concern:
//!
//! 1. All connections are end-to-end encrypted via QUIC/TLS
//! 2. Nodes are identified by Ed25519 public keys (EndpointId)
//! 3. Only authorized EndpointIds can establish tunnels
//! 4. The server verifies the connecting node's identity before allowing tunnel creation
//!
//! ## Multi-Port Protocol
//!
//! The protocol supports multiple named tunnels over a single connection:
//! 1. Client opens a bidirectional stream
//! 2. Client sends a tunnel request with the target name (e.g., "ssh", "postgres")
//! 3. Server validates the request and connects to the appropriate backend
//! 4. Bidirectional data flow begins

use anyhow::{Context, Result};
use iroh::{endpoint::Connection, protocol::{AcceptError, ProtocolHandler}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

use crate::security::AuthorizedKeys;

/// ALPN (Application-Layer Protocol Negotiation) identifier for our protocol
pub const ALPN: &[u8] = b"mole/tcp-tunnel/1";

/// Maximum size of tunnel request message (prevents DoS)
const MAX_REQUEST_SIZE: usize = 1024;

/// A tunnel target configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelTarget {
    /// Name of the tunnel (e.g., "ssh", "postgres", "web")
    pub name: String,
    /// Target address to connect to (e.g., "127.0.0.1:22")
    pub target_addr: String,
    /// Optional description
    pub description: Option<String>,
    /// Local port the client should listen on (hint for client)
    pub local_port: u16,
}

/// Tunnel request sent by client to open a specific tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRequest {
    /// Name of the tunnel to open
    pub tunnel_name: String,
}

/// Tunnel response sent by server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelResponse {
    /// Whether the tunnel was accepted
    pub accepted: bool,
    /// Error message if not accepted
    pub error: Option<String>,
}

/// Configuration for the tunnel server
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunnelConfig {
    /// Available tunnels, keyed by name
    pub tunnels: HashMap<String, TunnelTarget>,
}

impl TunnelConfig {
    /// Create a new empty config
    pub fn new() -> Self {
        Self {
            tunnels: HashMap::new(),
        }
    }

    /// Add a tunnel to the config
    pub fn add_tunnel(&mut self, target: TunnelTarget) {
        self.tunnels.insert(target.name.clone(), target);
    }

    /// Create a simple single-tunnel config (for backwards compatibility)
    pub fn single(name: &str, target_addr: &str, local_port: u16) -> Self {
        let mut config = Self::new();
        config.add_tunnel(TunnelTarget {
            name: name.to_string(),
            target_addr: target_addr.to_string(),
            description: None,
            local_port,
        });
        config
    }

    /// Create a default SSH-only config
    pub fn ssh_default() -> Self {
        Self::single("ssh", "127.0.0.1:22", 2222)
    }
}

/// The TCP tunnel protocol handler
///
/// This handler accepts incoming connections from authorized clients
/// and creates bidirectional tunnels to configured TCP services.
#[derive(Debug, Clone)]
pub struct TcpTunnelProtocol {
    /// Tunnel configuration
    config: Arc<TunnelConfig>,
    /// Authorized keys for access control
    authorized_keys: Arc<AuthorizedKeys>,
}

impl TcpTunnelProtocol {
    pub fn new(config: TunnelConfig, authorized_keys: AuthorizedKeys) -> Self {
        Self {
            config: Arc::new(config),
            authorized_keys: Arc::new(authorized_keys),
        }
    }

    /// Get the tunnel configuration
    pub fn config(&self) -> &TunnelConfig {
        &self.config
    }
}

impl ProtocolHandler for TcpTunnelProtocol {
    fn accept(
        &self,
        connection: Connection,
    ) -> impl Future<Output = Result<(), AcceptError>> + Send {
        let config = self.config.clone();
        let authorized_keys = self.authorized_keys.clone();

        async move {
            // Get the remote endpoint's ID for authentication
            let remote_endpoint_id = connection.remote_id();
            let remote_id_str = remote_endpoint_id.to_string();

            info!("Incoming connection from endpoint: {}", remote_id_str);

            // SECURITY: Verify the connecting endpoint is authorized
            if !authorized_keys.is_authorized(&remote_endpoint_id) {
                warn!(
                    "Rejected unauthorized connection attempt from: {}",
                    remote_id_str
                );

                // Close the connection with an error
                connection.close(1u32.into(), b"unauthorized");
                return Err(AcceptError::custom(format!(
                    "Unauthorized endpoint: {}",
                    remote_id_str
                )));
            }

            info!("Authorized connection from: {}", remote_id_str);

            // Handle multiple tunnel streams on this connection
            loop {
                // Accept a bidirectional stream for the tunnel
                let stream_result = connection.accept_bi().await;

                match stream_result {
                    Ok((send, recv)) => {
                        let config = config.clone();
                        let remote_id = remote_id_str.clone();

                        // Spawn a task to handle this tunnel stream
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_tunnel_stream(send, recv, &config, &remote_id).await
                            {
                                debug!("Tunnel stream ended: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        // Connection closed or error
                        debug!("Connection from {} closed: {}", remote_id_str, e);
                        break;
                    }
                }
            }

            Ok(())
        }
    }
}

/// Handle a single tunnel stream
async fn handle_tunnel_stream(
    mut iroh_send: iroh::endpoint::SendStream,
    mut iroh_recv: iroh::endpoint::RecvStream,
    config: &TunnelConfig,
    remote_id: &str,
) -> Result<()> {
    // Read the tunnel request
    let request = read_tunnel_request(&mut iroh_recv).await?;

    info!(
        "Tunnel request from {}: tunnel={}",
        remote_id, request.tunnel_name
    );

    // Look up the tunnel configuration
    let tunnel = match config.tunnels.get(&request.tunnel_name) {
        Some(t) => t,
        None => {
            warn!(
                "Unknown tunnel requested: {} from {}",
                request.tunnel_name, remote_id
            );
            let response = TunnelResponse {
                accepted: false,
                error: Some(format!("Unknown tunnel: {}", request.tunnel_name)),
            };
            send_tunnel_response(&mut iroh_send, &response).await?;
            return Err(anyhow!("Unknown tunnel: {}", request.tunnel_name));
        }
    };

    // Connect to the target
    let tcp_stream = match TcpStream::connect(&tunnel.target_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(
                "Failed to connect to {} for tunnel {}: {}",
                tunnel.target_addr, tunnel.name, e
            );
            let response = TunnelResponse {
                accepted: false,
                error: Some(format!("Backend connection failed: {}", e)),
            };
            send_tunnel_response(&mut iroh_send, &response).await?;
            return Err(anyhow!("Backend connection failed: {}", e));
        }
    };

    // Send success response
    let response = TunnelResponse {
        accepted: true,
        error: None,
    };
    send_tunnel_response(&mut iroh_send, &response).await?;

    info!(
        "Tunnel {} opened to {} for node {}",
        tunnel.name, tunnel.target_addr, remote_id
    );

    // Now do bidirectional copy
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    let copy_to_backend = async { tokio::io::copy(&mut iroh_recv, &mut tcp_write).await };

    let copy_from_backend = async { tokio::io::copy(&mut tcp_read, &mut iroh_send).await };

    // Run both copy operations concurrently
    tokio::select! {
        result = copy_to_backend => {
            match result {
                Ok(bytes) => debug!("Copied {} bytes to backend", bytes),
                Err(e) => debug!("Copy to backend ended: {}", e),
            }
        }
        result = copy_from_backend => {
            match result {
                Ok(bytes) => debug!("Copied {} bytes from backend", bytes),
                Err(e) => debug!("Copy from backend ended: {}", e),
            }
        }
    }

    // Signal that we're done sending
    let _ = iroh_send.finish();

    info!("Tunnel {} closed for node {}", tunnel.name, remote_id);
    Ok(())
}

/// Read a tunnel request from the stream
async fn read_tunnel_request(recv: &mut iroh::endpoint::RecvStream) -> Result<TunnelRequest> {
    // Read length prefix (4 bytes, big endian)
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("Failed to read request length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_REQUEST_SIZE {
        return Err(anyhow!("Request too large: {} bytes", len));
    }

    // Read the request body
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .context("Failed to read request body")?;

    let request: TunnelRequest =
        serde_json::from_slice(&buf).context("Failed to parse tunnel request")?;

    Ok(request)
}

/// Send a tunnel response on the stream
async fn send_tunnel_response(
    send: &mut iroh::endpoint::SendStream,
    response: &TunnelResponse,
) -> Result<()> {
    let data = serde_json::to_vec(response)?;
    let len = data.len() as u32;

    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&data).await?;

    Ok(())
}

/// Read a tunnel response from the stream (client-side)
pub async fn read_tunnel_response(recv: &mut iroh::endpoint::RecvStream) -> Result<TunnelResponse> {
    // Read length prefix (4 bytes, big endian)
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("Failed to read response length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_REQUEST_SIZE {
        return Err(anyhow!("Response too large: {} bytes", len));
    }

    // Read the response body
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .context("Failed to read response body")?;

    let response: TunnelResponse =
        serde_json::from_slice(&buf).context("Failed to parse tunnel response")?;

    Ok(response)
}

/// Send a tunnel request on the stream (client-side)
pub async fn send_tunnel_request(
    send: &mut iroh::endpoint::SendStream,
    request: &TunnelRequest,
) -> Result<()> {
    let data = serde_json::to_vec(request)?;
    let len = data.len() as u32;

    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&data).await?;

    Ok(())
}
