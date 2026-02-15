//! Client module for Mole
//!
//! The client runs on your local development machine. It connects to a
//! remote mole server and creates local TCP listeners that tunnel
//! connections through Iroh to configured remote services.

use anyhow::{anyhow, Context, Result};
use iroh::{Endpoint, EndpointId};
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::AsyncBufReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

use crate::protocol::{
    read_chat_message, read_tunnel_response, send_chat_message, send_tunnel_request,
    ChatMessage, TunnelRequest, ALPN, CHAT_ALPN,
};
use crate::security;

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
pub async fn run(endpoint_id_str: String, tunnel_bindings: Vec<TunnelBinding>) -> Result<()> {
    // Parse the endpoint ID
    let remote_endpoint_id = EndpointId::from_str(&endpoint_id_str)
        .map_err(|e| anyhow!("Invalid endpoint ID: {}", e))?;

    info!("Connecting to remote server: {}", remote_endpoint_id);

    // Create our endpoint with persistent identity
    let secret_key = security::load_or_generate_secret_key()
        .context("Failed to load or generate secret key")?;
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .bind()
        .await
        .context("Failed to create Iroh endpoint")?;

    let our_endpoint_id = endpoint.id();
    info!("Our endpoint ID: {}", our_endpoint_id);

    // Connect to the remote server
    info!("Establishing connection...");
    let connection = endpoint
        .connect(remote_endpoint_id, ALPN)
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

// ============================================================================
// Chat Client
// ============================================================================

use std::time::SystemTime;
use tokio::sync::Mutex;

/// Chat client for interactive chat sessions
pub struct ChatClient {
    endpoint: Endpoint,
    our_endpoint_id: String,
    send_stream: Arc<Mutex<iroh::endpoint::SendStream>>,
    recv_stream: Arc<Mutex<iroh::endpoint::RecvStream>>,
}

impl ChatClient {
    /// Connect to a chat endpoint
    pub async fn connect(endpoint_id_str: &str) -> Result<Self> {
        let remote_endpoint_id = EndpointId::from_str(endpoint_id_str)
            .map_err(|e| anyhow!("Invalid endpoint ID: {}", e))?;

        info!("Connecting to chat at: {}", remote_endpoint_id);

        // Create endpoint with chat ALPN
        let endpoint = Endpoint::builder()
            .alpns(vec![CHAT_ALPN.to_vec()])
            .bind()
            .await
            .context("Failed to create Iroh endpoint")?;

        let our_endpoint_id = endpoint.id().to_string();
        info!("Our endpoint ID: {}", our_endpoint_id);

        // Connect to the remote
        let connection = endpoint
            .connect(remote_endpoint_id, CHAT_ALPN)
            .await
            .context("Failed to connect to chat endpoint")?;

        info!("Connected to chat!");

        // Open bidirectional stream
        let (send, recv) = connection
            .open_bi()
            .await
            .context("Failed to open chat stream")?;

        Ok(Self {
            endpoint,
            our_endpoint_id,
            send_stream: Arc::new(Mutex::new(send)),
            recv_stream: Arc::new(Mutex::new(recv)),
        })
    }

    /// Get our endpoint ID
    pub fn our_endpoint_id(&self) -> &str {
        &self.our_endpoint_id
    }

    /// Send a chat message
    pub async fn send(&self, text: &str) -> Result<()> {
        let message = ChatMessage {
            sender: self.our_endpoint_id.clone(),
            text: text.to_string(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let mut send = self.send_stream.lock().await;
        send_chat_message(&mut *send, &message).await
    }

    /// Receive a chat message (blocking)
    pub async fn recv(&self) -> Result<ChatMessage> {
        let mut recv = self.recv_stream.lock().await;
        read_chat_message(&mut *recv).await
    }

    /// Close the chat connection
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}

/// Run an interactive chat session
pub async fn run_chat(endpoint_id_str: String) -> Result<()> {
    let client = ChatClient::connect(&endpoint_id_str).await?;

    println!();
    println!("========================================");
    println!("  Mole Chat");
    println!("========================================");
    println!();
    println!("Connected to: {}", endpoint_id_str);
    println!("Your ID:      {}", client.our_endpoint_id());
    println!();
    println!("Type messages and press Enter to send.");
    println!("Type /quit to exit.");
    println!();

    // Spawn receiver task
    let recv_stream = client.recv_stream.clone();
    let recv_handle = tokio::spawn(async move {
        loop {
            let mut recv = recv_stream.lock().await;
            match read_chat_message(&mut *recv).await {
                Ok(msg) => {
                    // Format timestamp
                    let secs = msg.timestamp % 86400;
                    let hours = secs / 3600;
                    let mins = (secs % 3600) / 60;
                    let secs = secs % 60;
                    
                    // Truncate sender ID for display
                    let sender_short = if msg.sender.len() > 8 {
                        &msg.sender[..8]
                    } else {
                        &msg.sender
                    };
                    
                    println!("[{:02}:{:02}:{:02}] {}: {}", hours, mins, secs, sender_short, msg.text);
                }
                Err(_) => {
                    println!("Chat connection closed.");
                    break;
                }
            }
        }
    });

    // Read from stdin and send
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();

    loop {
        print!("> ");
        use std::io::Write;
        std::io::stdout().flush().ok();
        
        match lines.next_line().await {
            Ok(Some(line)) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if line == "/quit" {
                    println!("Disconnecting...");
                    break;
                }
                if let Err(e) = client.send(line).await {
                    error!("Failed to send message: {}", e);
                    break;
                }
            }
            Ok(None) => {
                // EOF
                break;
            }
            Err(e) => {
                error!("Error reading input: {}", e);
                break;
            }
        }
    }

    recv_handle.abort();
    client.close().await;
    
    Ok(())
}
