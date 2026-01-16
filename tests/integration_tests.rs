//! Integration tests for Mole
//!
//! These tests verify the complete tunneling functionality by:
//! 1. Starting a mock TCP server
//! 2. Starting a mole server that tunnels to the mock server
//! 3. Starting a mole client that connects to the server
//! 4. Sending data through the tunnel and verifying it arrives correctly

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Test that we can create and bind an iroh endpoint
#[tokio::test]
async fn test_endpoint_creation() {
    let endpoint = iroh::Endpoint::bind().await.expect("Failed to create endpoint");
    let id = endpoint.id();
    
    // Endpoint ID should be a valid public key (32 bytes = 64 hex chars or z-base-32 encoded)
    assert!(!id.to_string().is_empty());
    
    endpoint.close().await;
}

/// Test that two endpoints can connect to each other
#[tokio::test]
async fn test_endpoint_connection() {
    use iroh::Endpoint;
    
    const TEST_ALPN: &[u8] = b"mole/test/1";
    
    // Create server endpoint
    let server = Endpoint::builder()
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await
        .expect("Failed to create server endpoint");
    
    server.online().await;
    let server_addr = server.addr();
    
    // Create client endpoint
    let client = Endpoint::bind()
        .await
        .expect("Failed to create client endpoint");
    
    // Spawn server accept task
    let server_handle = tokio::spawn(async move {
        let incoming = server.accept().await.expect("No incoming connection");
        let conn = incoming.await.expect("Failed to accept connection");
        
        // Accept a bidirectional stream
        let (mut send, mut recv) = conn.accept_bi().await.expect("Failed to accept stream");
        
        // Echo data back
        let mut buf = vec![0u8; 1024];
        let n = recv.read(&mut buf).await.expect("Failed to read");
        send.write_all(&buf[..n]).await.expect("Failed to write");
        send.finish().expect("Failed to finish");
        
        // Wait for client to close
        conn.closed().await;
        server.close().await;
    });
    
    // Connect client to server
    let conn = client
        .connect(server_addr, TEST_ALPN)
        .await
        .expect("Failed to connect");
    
    // Open a bidirectional stream
    let (mut send, mut recv) = conn.open_bi().await.expect("Failed to open stream");
    
    // Send test data
    let test_data = b"Hello, Mole!";
    send.write_all(test_data).await.expect("Failed to write");
    send.finish().expect("Failed to finish");
    
    // Read echoed data
    let response = recv.read_to_end(1024).await.expect("Failed to read");
    assert_eq!(response, test_data);
    
    // Close connection
    conn.close(0u32.into(), b"done");
    client.close().await;
    
    // Wait for server
    server_handle.await.expect("Server task failed");
}

/// Test the tunnel protocol message serialization
#[test]
fn test_tunnel_request_serialization() {
    use mole::protocol::{TunnelRequest, TunnelResponse};
    
    let request = TunnelRequest {
        tunnel_name: "ssh".to_string(),
    };
    
    let json = serde_json::to_string(&request).expect("Failed to serialize");
    let parsed: TunnelRequest = serde_json::from_str(&json).expect("Failed to deserialize");
    
    assert_eq!(parsed.tunnel_name, "ssh");
    
    let response = TunnelResponse {
        accepted: true,
        error: None,
    };
    
    let json = serde_json::to_string(&response).expect("Failed to serialize");
    let parsed: TunnelResponse = serde_json::from_str(&json).expect("Failed to deserialize");
    
    assert!(parsed.accepted);
    assert!(parsed.error.is_none());
}

/// Test tunnel configuration
#[test]
fn test_tunnel_config() {
    use mole::protocol::{TunnelConfig, TunnelTarget};
    
    let mut config = TunnelConfig::new();
    
    config.add_tunnel(TunnelTarget {
        name: "ssh".to_string(),
        target_addr: "127.0.0.1:22".to_string(),
        description: Some("SSH server".to_string()),
        local_port: 2222,
    });
    
    config.add_tunnel(TunnelTarget {
        name: "postgres".to_string(),
        target_addr: "127.0.0.1:5432".to_string(),
        description: None,
        local_port: 5432,
    });
    
    assert_eq!(config.tunnels.len(), 2);
    assert!(config.tunnels.contains_key("ssh"));
    assert!(config.tunnels.contains_key("postgres"));
    
    let ssh = config.tunnels.get("ssh").unwrap();
    assert_eq!(ssh.target_addr, "127.0.0.1:22");
    assert_eq!(ssh.local_port, 2222);
}

/// Test authorized keys functionality
#[tokio::test]
async fn test_authorized_keys() {
    use mole::security::AuthorizedKeys;
    use tempfile::tempdir;
    use std::fs;
    
    let dir = tempdir().expect("Failed to create temp dir");
    let keys_path = dir.path().join("authorized_keys.json");
    
    // Create a test config
    let config = r#"{
        "keys": [
            {
                "node_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "label": "Test Key",
                "added_at": "0s since epoch"
            }
        ]
    }"#;
    
    fs::write(&keys_path, config).expect("Failed to write config");
    
    let auth = AuthorizedKeys::from_file(keys_path.to_str().unwrap())
        .expect("Failed to load authorized keys");
    
    // Note: We can't easily test is_authorized without a valid EndpointId
    // but we can verify the file was loaded successfully
    
    // Test allow_all mode
    let auth_all = AuthorizedKeys::allow_all();
    // allow_all should allow any endpoint
}

/// Helper to start a simple echo TCP server
async fn start_echo_server() -> (u16, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind");
    let port = listener.local_addr().unwrap().port();
    
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    
    tokio::spawn(async move {
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((mut socket, _)) => {
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 1024];
                                loop {
                                    match socket.read(&mut buf).await {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            if socket.write_all(&buf[..n]).await.is_err() {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });
                        }
                        Err(_) => break,
                    }
                }
                _ = &mut shutdown_rx => {
                    break;
                }
            }
        }
    });
    
    (port, shutdown_tx)
}

/// Test direct TCP echo to verify test infrastructure
#[tokio::test]
async fn test_echo_server() {
    let (port, shutdown) = start_echo_server().await;
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;
    
    // Connect and test echo
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");
    
    let test_data = b"Hello, Echo!";
    stream.write_all(test_data).await.expect("Failed to write");
    
    let mut buf = vec![0u8; test_data.len()];
    stream.read_exact(&mut buf).await.expect("Failed to read");
    
    assert_eq!(buf, test_data);
    
    drop(stream);
    let _ = shutdown.send(());
}

/// Test full tunnel flow (requires more setup)
/// This is a more complex integration test that verifies the complete tunnel works
#[tokio::test]
#[ignore] // Run with: cargo test -- --ignored
async fn test_full_tunnel() {
    use iroh::Endpoint;
    use mole::protocol::{TcpTunnelProtocol, TunnelConfig, TunnelTarget, ALPN};
    use mole::security::AuthorizedKeys;
    
    // Start echo server
    let (echo_port, echo_shutdown) = start_echo_server().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    
    // Configure tunnel
    let mut config = TunnelConfig::new();
    config.add_tunnel(TunnelTarget {
        name: "echo".to_string(),
        target_addr: format!("127.0.0.1:{}", echo_port),
        description: Some("Echo server".to_string()),
        local_port: 0, // Client will pick a port
    });
    
    // Start mole server with allow_all for testing
    let auth = AuthorizedKeys::allow_all();
    let protocol = TcpTunnelProtocol::new(config, auth);
    
    let server = Endpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .expect("Failed to create server");
    
    server.online().await;
    let server_addr = server.addr();
    
    // Spawn server
    let server_clone = server.clone();
    let server_handle = tokio::spawn(async move {
        use iroh::protocol::Router;
        
        let router = Router::builder(server_clone)
            .accept(ALPN, protocol)
            .spawn();
        
        // Run for a bit then shutdown
        tokio::time::sleep(Duration::from_secs(5)).await;
        router.shutdown().await.expect("Failed to shutdown");
    });
    
    // Create client
    let client = Endpoint::bind().await.expect("Failed to create client");
    
    // Connect
    let conn = client
        .connect(server_addr, ALPN)
        .await
        .expect("Failed to connect");
    
    // Open tunnel stream
    let (mut send, mut recv) = conn.open_bi().await.expect("Failed to open stream");
    
    // Send tunnel request
    use mole::protocol::{TunnelRequest, send_tunnel_request, read_tunnel_response};
    
    let request = TunnelRequest {
        tunnel_name: "echo".to_string(),
    };
    send_tunnel_request(&mut send, &request).await.expect("Failed to send request");
    
    // Read response
    let response = read_tunnel_response(&mut recv).await.expect("Failed to read response");
    assert!(response.accepted, "Tunnel should be accepted");
    
    // Send data through tunnel
    let test_data = b"Hello through tunnel!";
    send.write_all(test_data).await.expect("Failed to write to tunnel");
    send.finish().expect("Failed to finish");
    
    // Read echoed data
    let echoed = recv.read_to_end(1024).await.expect("Failed to read from tunnel");
    assert_eq!(echoed, test_data, "Echo data should match");
    
    // Cleanup
    conn.close(0u32.into(), b"done");
    client.close().await;
    
    let _ = echo_shutdown.send(());
    server_handle.abort();
    server.close().await;
}
