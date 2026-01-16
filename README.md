# Mole

Secure SSH tunneling over [Iroh](https://iroh.computer) - access your development machine from anywhere without exposing ports to the public internet.

## Features

- **End-to-End Encrypted**: All traffic is encrypted using QUIC/TLS 1.3
- **No Port Forwarding Required**: Works through NAT and firewalls using Iroh's hole-punching
- **Authenticated Access**: Only nodes with authorized Ed25519 public keys can connect
- **Direct Connections**: Establishes direct peer-to-peer connections when possible, falls back to relays
- **Zero Configuration Networking**: No need to know IP addresses or configure DNS

## How It Works

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Your Laptop    │         │   Iroh Network  │         │  Dev Machine    │
│                 │         │                 │         │                 │
│  ssh localhost  │◄───────►│  E2E Encrypted  │◄───────►│  mole serve     │
│  :2222          │         │  QUIC Tunnel    │         │  → SSH :22      │
└─────────────────┘         └─────────────────┘         └─────────────────┘
```

1. Run `mole serve` on the machine you want to access (e.g., your home dev machine)
2. The server generates a connection ticket containing its public key and network info
3. Run `mole connect <ticket>` on your laptop to establish the tunnel
4. SSH to `localhost:2222` - traffic is tunneled securely to the remote machine

## Security Model

### Authentication

- Each node has a unique Ed25519 keypair (the NodeId)
- The server maintains an authorized_keys list of NodeIds allowed to connect
- Unauthorized connection attempts are rejected before any tunnel is established

### Encryption

- All connections use QUIC with TLS 1.3
- Traffic is end-to-end encrypted - even relay servers cannot read the content
- Perfect forward secrecy is provided by the TLS handshake

### Access Control

- By default, all connections are denied until keys are explicitly authorized
- Authorized keys are stored in `~/.config/mole/authorized_keys.json`
- File permissions are set to owner-only (600) automatically

## Installation

```bash
cargo install --path .
```

## Quick Start

### On your development machine (server):

```bash
# 1. Start the mole server
mole serve

# Note: On first run, all connections will be denied.
# The server will display a ticket - share this with your client.
```

### On your laptop (client):

```bash
# 1. Get your Node ID
mole info

# Share this Node ID with the server admin to get authorized
```

### Authorize the client (on server):

```bash
# Add the client's Node ID to authorized keys
mole keys add <client-node-id> --label "My Laptop"
```

### Connect from client:

```bash
# Connect using the server's ticket
mole connect <ticket>

# In another terminal, SSH through the tunnel
ssh -p 2222 localhost
```

## Usage

### Server Commands

```bash
# Start server (tunnels to local SSH on port 22)
mole serve

# Tunnel to a different SSH port
mole serve --ssh-addr 127.0.0.1:2222

# Use a custom authorized keys file
mole serve --authorized-keys /path/to/keys.json

# Just print the ticket and exit
mole serve --ticket

# Enable verbose logging
mole serve -v
```

### Client Commands

```bash
# Connect to a server
mole connect <ticket>

# Use a different local port
mole connect <ticket> --local-port 3333

# Enable verbose logging
mole connect -v <ticket>
```

### Key Management

```bash
# List authorized keys
mole keys list

# Add an authorized key
mole keys add <node-id> --label "Description"

# Remove an authorized key
mole keys remove <node-id>

# Generate a new identity and show Node ID
mole keys generate
```

### Information

```bash
# Show your Node ID and config location
mole info
```

## SSH Configuration

Add this to your `~/.ssh/config` for convenience:

```
Host dev-machine
    HostName localhost
    Port 2222
    User your-username
```

Then simply run:
```bash
mole connect <ticket>  # In one terminal
ssh dev-machine        # In another terminal
```

## Configuration Files

All configuration is stored in `~/.config/mole/`:

- `authorized_keys.json` - List of authorized Node IDs

### Example authorized_keys.json

```json
{
  "keys": [
    {
      "node_id": "fb970f941d38eb5ef357316f13a6dc24f35f74d3403b1b9de79bd698a6531a79",
      "label": "Work Laptop",
      "added_at": "1737043200s since epoch"
    }
  ]
}
```

## Troubleshooting

### Connection denied

Make sure your Node ID is in the server's authorized keys:
```bash
# On client: get your Node ID
mole info

# On server: add the Node ID
mole keys add <node-id> --label "description"
```

### Cannot reach server

- Check that the server is running (`mole serve`)
- Try enabling verbose logging (`-v` flag) to see connection details
- Ensure the ticket is complete (they can be long)

### SSH connection refused

- Verify SSH is running on the server: `systemctl status sshd`
- Check the SSH address: `mole serve --ssh-addr 127.0.0.1:22`

## License

MIT
