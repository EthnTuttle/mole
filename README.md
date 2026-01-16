# Mole

Secure TCP tunneling over [Iroh](https://iroh.computer) - access any service on your machine from anywhere without exposing ports to the public internet.

## Features

- **End-to-End Encrypted**: All traffic is encrypted using QUIC/TLS 1.3
- **No Port Forwarding Required**: Works through NAT and firewalls using Iroh's hole-punching
- **Authenticated Access**: Only nodes with authorized Ed25519 public keys can connect
- **Multi-Port Tunneling**: Tunnel multiple services (SSH, databases, web servers) over a single connection
- **Direct Connections**: Establishes direct peer-to-peer connections when possible, falls back to relays
- **Zero Configuration Networking**: No need to know IP addresses or configure DNS

## How It Works

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Your Laptop    │         │   Iroh Network  │         │  Dev Machine    │
│                 │         │                 │         │                 │
│  localhost:2222 │◄───────►│  E2E Encrypted  │◄───────►│  mole serve     │
│  localhost:5432 │         │  QUIC Tunnel    │         │    → SSH :22    │
│  localhost:3000 │         │                 │         │    → PG :5432   │
└─────────────────┘         └─────────────────┘         │    → Web :3000  │
                                                        └─────────────────┘
```

1. Run `mole serve` on the machine you want to access, specifying which services to expose
2. The server generates a connection ticket containing its public key and network info
3. Run `mole connect <ticket>` on your laptop to establish tunnels
4. Access services on localhost - traffic is tunneled securely to the remote machine

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

### Single Service (SSH)

```bash
# On your dev machine (server):
mole serve

# On your laptop (client):
mole info                    # Get your Node ID
# Share Node ID with server admin to get authorized

# Once authorized:
mole connect <ticket>
ssh -p 2222 localhost
```

### Multiple Services

```bash
# On your dev machine - expose SSH, PostgreSQL, and a web server:
mole serve \
  -t ssh:127.0.0.1:22:2222 \
  -t postgres:127.0.0.1:5432:5432 \
  -t web:127.0.0.1:3000:8080

# On your laptop - connect to all services:
mole connect <ticket> \
  -t ssh:2222 \
  -t postgres:5432 \
  -t web:8080

# Now access everything locally:
ssh -p 2222 localhost
psql -h localhost -p 5432 -U postgres
curl http://localhost:8080
```

## Usage

### Server Commands

```bash
# Start server with default SSH tunnel (127.0.0.1:22 → client:2222)
mole serve

# Expose multiple services
mole serve \
  -t ssh:127.0.0.1:22:2222 \
  -t postgres:127.0.0.1:5432:5432 \
  -t redis:127.0.0.1:6379:6379

# Tunnel spec format: name:host:port[:local_port]
# If local_port is omitted, it defaults to the same as the target port

# Use a custom authorized keys file
mole serve --authorized-keys /path/to/keys.json

# Just print the ticket and exit
mole serve --ticket

# Enable verbose logging
mole serve -v
```

### Client Commands

```bash
# Connect with default SSH tunnel
mole connect <ticket>

# Connect with specific tunnels
mole connect <ticket> -t ssh:2222 -t postgres:5432

# Tunnel binding format: name:local_port
# The name must match a tunnel configured on the server

# Enable verbose logging
mole connect -v <ticket>
```

### Key Management

```bash
# List authorized keys
mole keys list

# Add an authorized key
mole keys add <node-id> --label "Work Laptop"

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

## Common Use Cases

### Remote Development with SSH

```bash
# Server
mole serve -t ssh:127.0.0.1:22:2222

# Client
mole connect <ticket>
ssh -p 2222 localhost

# Or with VS Code Remote SSH (add to ~/.ssh/config):
Host dev-machine
    HostName localhost
    Port 2222
    User your-username
```

### Database Access

```bash
# Server - expose PostgreSQL and Redis
mole serve \
  -t postgres:127.0.0.1:5432:5432 \
  -t redis:127.0.0.1:6379:6379

# Client
mole connect <ticket> -t postgres:5432 -t redis:6379

# Connect to databases
psql -h localhost -p 5432 -U postgres
redis-cli -p 6379
```

### Web Development

```bash
# Server - expose your dev server
mole serve -t web:127.0.0.1:3000:8080

# Client
mole connect <ticket> -t web:8080

# Access in browser
open http://localhost:8080
```

### Full Development Stack

```bash
# Server - expose everything you need
mole serve \
  -t ssh:127.0.0.1:22:2222 \
  -t postgres:127.0.0.1:5432:5432 \
  -t redis:127.0.0.1:6379:6379 \
  -t web:127.0.0.1:3000:3000 \
  -t api:127.0.0.1:8000:8000

# Client - connect to all
mole connect <ticket> \
  -t ssh:2222 \
  -t postgres:5432 \
  -t redis:6379 \
  -t web:3000 \
  -t api:8000
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
    },
    {
      "node_id": "a1b2c3d4e5f6...",
      "label": "Home Desktop",
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

### Tunnel rejected

- Make sure the tunnel name on the client matches one configured on the server
- Check verbose logs on both sides for details

### Service connection refused

- Verify the service is running on the server (e.g., `systemctl status sshd`)
- Check the target address in the server's tunnel config

## License

MIT
