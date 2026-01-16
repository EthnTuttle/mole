//! Security module for Mole
//!
//! Handles:
//! - Authorized keys management (which nodes can connect)
//! - Node identity persistence
//! - Configuration storage

use anyhow::{anyhow, Context, Result};
use iroh::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::info;

/// Get the configuration directory for mole
pub fn config_dir() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .ok_or_else(|| anyhow!("Could not determine config directory"))?
        .join("mole");

    // Ensure directory exists with proper permissions
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        // On Unix, set directory permissions to 700 (owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
    }

    Ok(dir)
}

/// Get the path to the authorized keys file
pub fn authorized_keys_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("authorized_keys.json"))
}

/// Entry in the authorized keys file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedKeyEntry {
    /// The node ID (Ed25519 public key)
    pub node_id: String,
    /// Optional human-readable label
    pub label: Option<String>,
    /// When this key was added
    pub added_at: String,
}

/// Authorized keys configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthorizedKeysConfig {
    /// List of authorized keys
    pub keys: Vec<AuthorizedKeyEntry>,
}

/// Runtime authorized keys checker
#[derive(Debug)]
pub struct AuthorizedKeys {
    /// Map of authorized node IDs to their labels
    authorized: HashMap<NodeId, Option<String>>,
    /// Whether to allow all connections (no authorization required)
    allow_all: bool,
}

impl AuthorizedKeys {
    /// Load authorized keys from a file path
    pub fn from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read authorized keys from {}", path))?;

        let config: AuthorizedKeysConfig =
            serde_json::from_str(&content).with_context(|| "Failed to parse authorized keys")?;

        let mut authorized = HashMap::new();
        for entry in config.keys {
            let node_id = NodeId::from_str(&entry.node_id)
                .with_context(|| format!("Invalid node ID: {}", entry.node_id))?;
            authorized.insert(node_id, entry.label);
        }

        info!("Loaded {} authorized key(s)", authorized.len());
        Ok(Self {
            authorized,
            allow_all: false,
        })
    }

    /// Load from the default config location
    pub fn from_default_config() -> Result<Self> {
        let path = authorized_keys_path()?;
        if path.exists() {
            Self::from_file(path.to_str().unwrap())
        } else {
            // No authorized keys file - deny all by default for security
            info!("No authorized keys file found - all connections will be denied");
            info!(
                "Add authorized keys with: mole keys add <node_id> --label <description>"
            );
            Ok(Self {
                authorized: HashMap::new(),
                allow_all: false,
            })
        }
    }

    /// Create an AuthorizedKeys that allows all connections
    /// WARNING: This should only be used for initial setup/testing
    pub fn allow_all() -> Self {
        Self {
            authorized: HashMap::new(),
            allow_all: true,
        }
    }

    /// Check if a node ID is authorized
    pub fn is_authorized(&self, node_id: &NodeId) -> bool {
        if self.allow_all {
            return true;
        }
        self.authorized.contains_key(node_id)
    }

    /// Get the label for an authorized node
    pub fn get_label(&self, node_id: &NodeId) -> Option<&str> {
        self.authorized.get(node_id).and_then(|l| l.as_deref())
    }
}

/// List all authorized keys
pub fn list_authorized_keys() -> Result<()> {
    let path = authorized_keys_path()?;

    if !path.exists() {
        println!("No authorized keys configured.");
        println!();
        println!("Add keys with: mole keys add <node_id> --label <description>");
        return Ok(());
    }

    let content = fs::read_to_string(&path)?;
    let config: AuthorizedKeysConfig = serde_json::from_str(&content)?;

    if config.keys.is_empty() {
        println!("No authorized keys configured.");
        return Ok(());
    }

    println!("Authorized Keys:");
    println!("================");
    for entry in &config.keys {
        let label = entry.label.as_deref().unwrap_or("(no label)");
        println!();
        println!("  Node ID: {}", entry.node_id);
        println!("  Label:   {}", label);
        println!("  Added:   {}", entry.added_at);
    }
    println!();
    println!("Total: {} key(s)", config.keys.len());

    Ok(())
}

/// Add a new authorized key
pub fn add_authorized_key(node_id: &str, label: Option<&str>) -> Result<()> {
    // Validate the node ID format
    NodeId::from_str(node_id).with_context(|| format!("Invalid node ID format: {}", node_id))?;

    let path = authorized_keys_path()?;

    let mut config = if path.exists() {
        let content = fs::read_to_string(&path)?;
        serde_json::from_str(&content)?
    } else {
        AuthorizedKeysConfig::default()
    };

    // Check if already exists
    if config.keys.iter().any(|k| k.node_id == node_id) {
        return Err(anyhow!("Node ID is already authorized"));
    }

    // Add the new key
    let entry = AuthorizedKeyEntry {
        node_id: node_id.to_string(),
        label: label.map(String::from),
        added_at: chrono_lite_timestamp(),
    };

    config.keys.push(entry);

    // Write back
    let content = serde_json::to_string_pretty(&config)?;
    fs::write(&path, content)?;

    // Set file permissions to 600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    println!("Added authorized key:");
    println!("  Node ID: {}", node_id);
    if let Some(l) = label {
        println!("  Label:   {}", l);
    }

    Ok(())
}

/// Remove an authorized key
pub fn remove_authorized_key(node_id: &str) -> Result<()> {
    let path = authorized_keys_path()?;

    if !path.exists() {
        return Err(anyhow!("No authorized keys file found"));
    }

    let content = fs::read_to_string(&path)?;
    let mut config: AuthorizedKeysConfig = serde_json::from_str(&content)?;

    let initial_len = config.keys.len();
    config.keys.retain(|k| k.node_id != node_id);

    if config.keys.len() == initial_len {
        return Err(anyhow!("Node ID not found in authorized keys"));
    }

    let content = serde_json::to_string_pretty(&config)?;
    fs::write(&path, content)?;

    println!("Removed authorized key: {}", node_id);

    Ok(())
}

/// Generate a new node identity and display its ID
pub async fn generate_identity() -> Result<()> {
    use iroh::Endpoint;

    // Create a new endpoint which generates a new identity
    let endpoint = Endpoint::bind().await?;
    let node_id = endpoint.node_id();

    println!("Generated new node identity");
    println!();
    println!("Node ID: {}", node_id);
    println!();
    println!("Share this Node ID with mole servers to get authorized access.");
    println!("Run 'mole info' anytime to see your Node ID.");

    endpoint.close().await;
    Ok(())
}

/// Simple timestamp without requiring the chrono crate
fn chrono_lite_timestamp() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}s since epoch", duration.as_secs())
}
