//! SSH Tunnel Protocol for Mole
//!
//! This module defines the protocol used for tunneling SSH connections over Iroh.
//! The protocol is designed with security as a primary concern:
//!
//! 1. All connections are end-to-end encrypted via QUIC/TLS
//! 2. Nodes are identified by Ed25519 public keys (NodeId)
//! 3. Only authorized NodeIds can establish tunnels
//! 4. The server verifies the connecting node's identity before allowing tunnel creation

use anyhow::{anyhow, Result};
use iroh::{endpoint::Connection, protocol::ProtocolHandler};
use n0_future::boxed::BoxFuture;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

use crate::security::AuthorizedKeys;

/// ALPN (Application-Layer Protocol Negotiation) identifier for our protocol
pub const ALPN: &[u8] = b"mole/ssh-tunnel/1";

/// The SSH tunnel protocol handler
///
/// This handler accepts incoming connections from authorized clients
/// and creates bidirectional tunnels to the local SSH server.
#[derive(Debug, Clone)]
pub struct SshTunnelProtocol {
    /// Address of the local SSH server to tunnel to
    ssh_addr: String,
    /// Authorized keys for access control
    authorized_keys: Arc<AuthorizedKeys>,
}

impl SshTunnelProtocol {
    pub fn new(ssh_addr: String, authorized_keys: AuthorizedKeys) -> Self {
        Self {
            ssh_addr,
            authorized_keys: Arc::new(authorized_keys),
        }
    }
}

impl ProtocolHandler for SshTunnelProtocol {
    fn accept(&self, connection: Connection) -> BoxFuture<Result<()>> {
        let ssh_addr = self.ssh_addr.clone();
        let authorized_keys = self.authorized_keys.clone();

        Box::pin(async move {
            // Get the remote node's ID for authentication
            let remote_node_id = connection.remote_node_id()?;
            let remote_id_str = remote_node_id.to_string();

            info!("Incoming connection from node: {}", remote_id_str);

            // SECURITY: Verify the connecting node is authorized
            if !authorized_keys.is_authorized(&remote_node_id) {
                warn!(
                    "Rejected unauthorized connection attempt from: {}",
                    remote_id_str
                );

                // Close the connection with an error
                connection.close(1u32.into(), b"unauthorized");
                return Err(anyhow!("Unauthorized node: {}", remote_id_str));
            }

            info!("Authorized connection from: {}", remote_id_str);

            // Handle multiple tunnel streams on this connection
            loop {
                // Accept a bidirectional stream for the tunnel
                let stream_result = connection.accept_bi().await;

                match stream_result {
                    Ok((send, recv)) => {
                        let ssh_addr = ssh_addr.clone();
                        let remote_id = remote_id_str.clone();

                        // Spawn a task to handle this tunnel stream
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_tunnel_stream(send, recv, &ssh_addr, &remote_id).await
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
        })
    }
}

/// Handle a single tunnel stream by connecting to the SSH server
/// and bidirectionally copying data
async fn handle_tunnel_stream(
    mut iroh_send: iroh::endpoint::SendStream,
    mut iroh_recv: iroh::endpoint::RecvStream,
    ssh_addr: &str,
    remote_id: &str,
) -> Result<()> {
    info!("Opening tunnel to {} for node {}", ssh_addr, remote_id);

    // Connect to the local SSH server
    let tcp_stream = TcpStream::connect(ssh_addr).await.map_err(|e| {
        error!("Failed to connect to SSH server at {}: {}", ssh_addr, e);
        anyhow!("SSH server connection failed: {}", e)
    })?;

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // Bidirectionally copy data between the Iroh stream and TCP connection
    // This creates the actual tunnel
    let copy_to_ssh = async {
        tokio::io::copy(&mut iroh_recv, &mut tcp_write).await
    };

    let copy_from_ssh = async {
        tokio::io::copy(&mut tcp_read, &mut iroh_send).await
    };

    // Run both copy operations concurrently
    // When either side closes, the tunnel ends
    tokio::select! {
        result = copy_to_ssh => {
            match result {
                Ok(bytes) => debug!("Copied {} bytes to SSH server", bytes),
                Err(e) => debug!("Copy to SSH ended: {}", e),
            }
        }
        result = copy_from_ssh => {
            match result {
                Ok(bytes) => debug!("Copied {} bytes from SSH server", bytes),
                Err(e) => debug!("Copy from SSH ended: {}", e),
            }
        }
    }

    // Signal that we're done sending
    let _ = iroh_send.finish();

    info!("Tunnel closed for node {}", remote_id);
    Ok(())
}
