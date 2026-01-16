//! Server module for Mole
//!
//! The server runs on the host machine that you want to access remotely.
//! It accepts incoming Iroh connections from authorized clients and tunnels
//! them to configured TCP services.

use anyhow::{Context, Result};
use iroh::protocol::Router;
use iroh::Endpoint;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::protocol::{TcpTunnelProtocol, TunnelConfig, TunnelTarget, ALPN};
use crate::security::AuthorizedKeys;

/// Server configuration with tunnels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Tunnel configurations
    pub tunnels: Vec<TunnelTarget>,
}

/// Run the mole server
pub async fn run(
    tunnel_specs: Vec<String>,
    authorized_keys_path: Option<String>,
    ticket_only: bool,
) -> Result<()> {
    // Parse tunnel specifications
    let config = parse_tunnel_specs(&tunnel_specs)?;

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

    let endpoint_id = endpoint.id();
    info!("Server endpoint ID: {}", endpoint_id);

    // Get the endpoint address for sharing
    let addr = endpoint.addr();
    let addr_str = addr.to_string();

    // Create the protocol handler
    let protocol = TcpTunnelProtocol::new(config.clone(), authorized_keys);

    if ticket_only {
        // Just print the address and exit
        println!("{}", addr_str);
        endpoint.close().await;
        return Ok(());
    }

    // Print connection information
    println!();
    println!("========================================");
    println!("  Mole TCP Tunnel Server");
    println!("========================================");
    println!();
    println!("Endpoint ID: {}", endpoint_id);
    println!();
    println!("Available Tunnels:");
    for (name, target) in &config.tunnels {
        let desc = target
            .description
            .as_deref()
            .unwrap_or("no description");
        println!(
            "  {} -> {} (client port: {}) - {}",
            name, target.target_addr, target.local_port, desc
        );
    }
    println!();
    println!("Connection Address (share with clients):");
    println!();
    println!("{}", addr_str);
    println!();
    println!("========================================");
    println!();
    println!("Clients can connect with:");
    println!("  mole connect {}", addr_str);
    println!();
    println!("Waiting for connections... (Ctrl+C to stop)");
    println!();

    // Build and spawn the router
    let router = Router::builder(endpoint).accept(ALPN, protocol).spawn();

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

/// Parse tunnel specifications from command line
///
/// Format: name:target_addr:local_port or name:target_addr (local_port auto-assigned)
/// Examples:
///   - ssh:127.0.0.1:22:2222
///   - postgres:127.0.0.1:5432:5432
///   - web:127.0.0.1:3000:3000
fn parse_tunnel_specs(specs: &[String]) -> Result<TunnelConfig> {
    let mut config = TunnelConfig::new();

    // If no specs provided, use default SSH
    if specs.is_empty() {
        config.add_tunnel(TunnelTarget {
            name: "ssh".to_string(),
            target_addr: "127.0.0.1:22".to_string(),
            description: Some("SSH server".to_string()),
            local_port: 2222,
        });
        return Ok(config);
    }

    for spec in specs {
        let parts: Vec<&str> = spec.split(':').collect();

        let target = match parts.len() {
            // name:host:port:local_port
            4 => TunnelTarget {
                name: parts[0].to_string(),
                target_addr: format!("{}:{}", parts[1], parts[2]),
                description: None,
                local_port: parts[3]
                    .parse()
                    .with_context(|| format!("Invalid local port in: {}", spec))?,
            },
            // name:host:port (auto-assign local port same as target)
            3 => {
                let port: u16 = parts[2]
                    .parse()
                    .with_context(|| format!("Invalid port in: {}", spec))?;
                TunnelTarget {
                    name: parts[0].to_string(),
                    target_addr: format!("{}:{}", parts[1], parts[2]),
                    description: None,
                    local_port: port,
                }
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid tunnel spec: {}. Expected format: name:host:port[:local_port]",
                    spec
                ));
            }
        };

        config.add_tunnel(target);
    }

    Ok(config)
}
