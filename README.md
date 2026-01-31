# quicport

QUIC-based port forwarding / tunneling tool.

Expose local services behind NAT to the internet through a QUIC tunnel with mutual authentication.

## Features

- **QUIC transport**: Secure, multiplexed connections over UDP with TLS 1.3
- **Mutual authentication**: X25519 key-based authentication for both server and client
- **PSK authentication**: Simple pre-shared key authentication for quick setup
- **NAT traversal**: Expose local services behind NAT/firewall to the internet
- **Built-in API server**: Health check endpoint for monitoring and orchestration
- **Library support**: Use as a library in your Rust applications

## Use Case

```
[External Client] --> [Server:9022/tcp] --QUIC--> [Client:22/tcp (behind NAT)]
```

Example: Expose an SSH server behind NAT to the internet via a QUIC tunnel.

## Installation

### Using pre-built binary

Download the latest binary for your platform from [GitHub Releases](https://github.com/hakadoriya/quicport/releases).

```bash
# Example for *nix
sh -cx 'VERSION=v0.0.1 && curl -LRSs https://github.com/hakadoriya/quicport/releases/download/${VERSION}/quicport_$(uname -s)_$(uname -m).zip -o /tmp/quicport.zip && unzip -d /tmp -o /tmp/quicport.zip quicport && sudo mv /tmp/quicport /usr/local/bin/quicport'
```

Available binaries follow the naming convention: `quicport_<OS>_<arch>.zip`
- Linux: `quicport_Linux_x86_64.zip`, `quicport_Linux_arm64.zip`
- macOS: `quicport_Darwin_x86_64.zip`, `quicport_Darwin_arm64.zip`
- Windows: `quicport_Windows_x86_64.zip`, `quicport_Windows_arm64.zip`

### From source

```bash
git clone https://github.com/hakadoriya/quicport.git
cd quicport
cargo install --path .
```

## Quick Start

### 1. Generate keys (for X25519 authentication)

Using WireGuard's `wg` command (outputs Base64 format directly):

```bash
# Generate server keypair
wg genkey | tee server.key | wg pubkey > server.pub

# Generate client keypair
wg genkey | tee client.key | wg pubkey > client.pub

# View keys
cat server.key  # Server private key (Base64)
cat server.pub  # Server public key (Base64)
cat client.key  # Client private key (Base64)
cat client.pub  # Client public key (Base64)
```

### 2. Start the server

```bash
quicport control-plane \
  --data-plane-addr 0.0.0.0:39000 \
  --privkey "SERVER_PRIVATE_KEY_BASE64" \
  --client-pubkeys "CLIENT_PUBLIC_KEY_BASE64"
```

### 3. Start the client

```bash
quicport client \
  --server your-server.example.com:39000 \
  --remote-source 9022 \
  --local-destination 22 \
  --privkey "CLIENT_PRIVATE_KEY_BASE64" \
  --server-pubkey "SERVER_PUBLIC_KEY_BASE64"
```

### 4. Connect to the forwarded port

```bash
ssh -p 9022 user@your-server.example.com
```

## Usage

### Control Plane Mode

```bash
quicport control-plane [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--control-plane-addr` | `127.0.0.1:39000` | Address and port for control-plane HTTP IPC server |
| `--data-plane-addr` | `0.0.0.0:39000` | Address and port for data-plane QUIC listen |
| `--private-api-listen` | `127.0.0.1:<port>` | Address for private API server (same port as QUIC, TCP) |
| `--no-public-api` | `false` | Disable public API server (/healthcheck, port+1) |
| `--no-auto-dataplane` | `false` | Do not automatically start a data-plane process |
| `--privkey` | - | Server's private key (Base64). Env: `QUICPORT_PRIVKEY` |
| `--privkey-file` | - | Path to server's private key file. Env: `QUICPORT_PRIVKEY_FILE` |
| `--client-pubkeys` | - | Authorized client public keys (comma-separated). Env: `QUICPORT_CLIENT_PUBKEYS` |
| `--client-pubkeys-file` | - | Path to file with client public keys (one per line). Env: `QUICPORT_CLIENT_PUBKEYS_FILE` |
| `--psk` | - | Pre-shared key for authentication. Env: `QUICPORT_PSK` |

### Client Mode

```bash
quicport client [OPTIONS] --server <SERVER> --remote-source <PORT> --local-destination [ADDR:]<PORT>
```

| Option | Required | Description |
|--------|----------|-------------|
| `-s, --server` | Yes | Server address to connect to |
| `-r, --remote-source` | Yes | Remote port to open on server (e.g., `9022` or `9022/tcp`) |
| `-l, --local-destination` | Yes | Local destination (e.g., `22`, `192.168.1.100:22`). Default addr: `127.0.0.1` |
| `--privkey` | * | Client's private key (Base64). Env: `QUICPORT_PRIVKEY` |
| `--privkey-file` | * | Path to client's private key file. Env: `QUICPORT_PRIVKEY_FILE` |
| `--server-pubkey` | ** | Expected server's public key (Base64). Env: `QUICPORT_SERVER_PUBKEY` |
| `--server-pubkey-file` | ** | Path to server's public key file. Env: `QUICPORT_SERVER_PUBKEY_FILE` |
| `--psk` | * | Pre-shared key for authentication. Env: `QUICPORT_PSK` |

\* Either `--privkey`/`--privkey-file` or `--psk` is required
\** Required when using X25519 authentication (to prevent MITM attacks)

## Authentication

### X25519 Mutual Authentication (Recommended)

Both server and client authenticate each other using X25519 key pairs:

```bash
# Server
quicport control-plane \
  --privkey "SERVER_PRIVATE_KEY" \
  --client-pubkeys "CLIENT_PUBLIC_KEY"

# Client
quicport client \
  --server example.com:39000 \
  -r 9022/tcp -l 22/tcp \
  --privkey "CLIENT_PRIVATE_KEY" \
  --server-pubkey "SERVER_PUBLIC_KEY"
```

### PSK Authentication (Simple)

For quick setup or testing, use a pre-shared key:

```bash
# Server
quicport control-plane --psk "your-secret-key"

# Client
quicport client \
  --server example.com:39000 \
  -r 9022/tcp -l 22/tcp \
  --psk "your-secret-key"
```

## API Server

The server provides two HTTP API servers:

### Private API (same port as QUIC, TCP, localhost only)

Accessible only from localhost. Provides `/healthcheck`, `/metrics`, and `/api/v1/*` endpoints.

```bash
# Health check
curl http://127.0.0.1:39000/healthcheck

# Prometheus metrics
curl http://127.0.0.1:39000/metrics
```

Change address with `--private-api-listen`.

### Public API (QUIC port + 1, TCP)

Accessible from the internet. Only `/healthcheck` endpoint is exposed.

```bash
# Health check endpoint (from anywhere)
curl http://your-server:39001/healthcheck
# Response: {"status":"SERVING"}
```

Disable with `--no-public-api` flag.

## Library Usage

quicport can be used as a library in your Rust applications:

```rust
use quicport::control_plane;
use quicport::ipc::AuthPolicy;
use quicport::statistics::ServerStatistics;
use quicport::client::{self, ClientAuthConfig, ReconnectConfig};
use std::net::SocketAddr;
use std::sync::Arc;

// Start server (control plane)
let cp_addr: SocketAddr = "127.0.0.1:39000".parse()?;
let dp_addr: SocketAddr = "0.0.0.0:39000".parse()?;
let auth_policy = AuthPolicy::Psk { psk: "secret".to_string() };
let statistics = Arc::new(ServerStatistics::new());
control_plane::run_with_api(
    cp_addr, dp_addr, auth_policy, statistics,
    None, false, "console".to_string(), None, 5, 90,
).await?;

// Start client
let auth = ClientAuthConfig::Psk { psk: "secret".to_string() };
let reconnect = ReconnectConfig::default();
client::run_remote_forward_with_reconnect(
    "127.0.0.1:39000", "8080/tcp", "80/tcp", auth, false, reconnect, 5, 90,
).await?;
```

## Systemd Service

Example is available in [`platform/linux/systemd/quicport.service`](platform/linux/systemd/quicport.service).

### Graceful Restart Behavior

| Operation | Result |
|-----------|--------|
| `systemctl reload quicport` | Graceful restart, **connections preserved** |
| `systemctl stop/restart quicport` | **Refused** (protected by `RefuseManualStop=yes`) |
| OS shutdown | All processes terminated, connections dropped (acceptable) |
| Emergency stop | `systemctl kill -s SIGKILL quicport` |

**Why not `systemctl restart`?**

systemd manages processes by **cgroup**. When a service stops, all processes in its cgroup are terminated. This includes data-plane processes that maintain active connections. Unlike sshd (where `systemd-logind` moves SSH sessions to a separate cgroup), quicport data-planes remain in the service's cgroup.

The solution: Use `systemctl reload` for graceful restarts. This triggers `ExecReload` which sends DRAIN commands to existing data-planes while starting new ones. Data-planes continue serving existing connections until they naturally close.

## Building from Source

```bash
# Clone the repository
git clone https://github.com/hakadoriya/quicport.git
cd quicport

# Build
cargo build --release

# Run tests
cargo test

# Install locally
cargo install --path .
```

## License

Apache-2.0
