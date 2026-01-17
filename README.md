# shelley-lxc | Incus Container Manager

An Incus/LXC-based platform for self-hosting persistent AI coding agent sandboxes with Caddy reverse proxy and direct SSH routing to containers (suitable for VS Code remote ssh).

Create and host your vibe-coded apps on a single VPS/server.

## *UPFRONT DISCLOSURE*

This project is 99.9% vibe-coded on the [exe.dev](https://exe.dev/docs/list) platform using their Shelley Web AI Coding Agent and Claude Opus 4.5.
Take that as you will.

With that said, I am a huge proponent of the exe.dev platform, and if you can, you should definitely try it out and use their service. The love and care for that project/service is extremely evident... AND it is incredibly awesome (and I think it's in its infancy stages, so should only get better).

## *WARNING*

This is extremely alpha software and a very new project. Feel free to test and experiment but it's likely to have bugs and definitely not ready for production. Use at your own risk.

## What is this?

This project provides the infrastructure to self-host your own AI coding environment on virtually any Linux server -- a VPS, cloud VM (EC2, GCP, Azure), or dedicated hardware. Because it uses **Incus/LXC** (container-based virtualization rather than nested VMs), it runs efficiently on KVM, VMware, Xen, Hyper-V, and most other hypervisors.

Each container is a fully persistent Linux sandbox running **Ubuntu 24.04 LTS** or **Debian 12**, with:

- **[shelley-cli](https://github.com/davidcjones79/shelley-cli)** - Terminal-based AI coding agent (fork with additional features)
- **Your app/site** accessible via HTTPS at `yourdomain.com`
- **SSH access** for direct terminal access to your sandbox (suitable for VS Code remote ssh)
- **Persistent filesystem** that survives container restarts
- **Pre-installed development tools**: Docker, Go, Node.js

### Use Cases

- **AI-assisted development**: Use shelley-cli as your AI pair programmer with full system access
- **Vibe coding**: Spin up isolated sandboxes for experimental projects
- **App/site hosting**: Deploy and iterate on web applications
- **Learning environments**: Safe, isolated Linux environments for experimentation
- **CI/CD sandboxes**: Temporary or persistent build environments

### Stack Overview

| Component | Purpose |
|-----------|--------|
| **Incus (LXC)** | Container runtime - lightweight, persistent Linux containers |
| **Caddy** | Reverse proxy with automatic HTTPS (Let's Encrypt) |
| **SSHPiper** | SSH routing - access any container via `ssh -p 2222 container-name@host` |
| **Ubuntu/Debian** | Native Incus images (user choice during creation) |
| **shelley-cli** | Terminal-based AI coding agent |

### shelley-cli

This project uses [shelley-cli](https://github.com/davidcjones79/shelley-cli), a fork of [boldsoftware/shelley-cli](https://github.com/boldsoftware/shelley-cli) with additional features. shelley-cli provides both a **terminal interface** and a **web UI** (on port 9999) for AI-assisted coding. It supports multiple LLM providers:

- **Anthropic** (Claude models)
- **OpenAI** (GPT models)
- **Fireworks** (Open source models)

You can also configure custom API endpoints (e.g., Azure OpenAI, local models, or other proxies).

## Components

- `incus_manager` - Interactive TUI for container management
- `incus_sync_daemon` - Background service for config synchronization

## Prerequisites

- **Fresh/minimal Linux installation**: Ubuntu 22.04+ or Debian 12+ (amd64 or arm64)
- **VPS or VM**: Works on most virtualization platforms (KVM, VMware, Xen, EC2, GCP, Azure, etc.)
- **Go 1.21+**: Required to build the tools (see Quick Start for installation)
- **A domain name** with DNS you control
- **An LLM API key** (Anthropic, OpenAI, or Fireworks)
- **A regular user with sudo access** (avoid running as root)

### Security Recommendations

Before installing, ensure your host SSH is properly secured:

```bash
# In /etc/ssh/sshd_config, verify these settings:
PermitRootLogin no
PasswordAuthentication no
```

All administrative tasks should be performed as a regular user with `sudo` privileges, not as root directly.

## Quick Start

### 1. Install Go (if not already installed)

```bash
# Install wget & git
sudo apt update && sudo apt install wget git

# Ubuntu/Debian - install from official Go downloads
wget https://go.dev/dl/go1.23.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify installation
go version
```

> **Note**: For ARM64 systems, use `go1.23.5.linux-arm64.tar.gz` instead.
> Check https://go.dev/dl/ for the latest version.

### 2. Build and Install

```bash
# Clone and build
git clone https://github.com/jgbrwn/shelley-lxc.git
cd shelley-lxc
git checkout native_incus_containers  # Use the new branch
go build -o incus_manager incus_manager.go
go build -o incus_sync_daemon incus_sync_daemon.go

# Install binaries
sudo cp incus_manager incus_sync_daemon /usr/local/bin/
```

### 3. Run First-Time Setup

```bash
# This auto-installs Incus, Caddy, and SSHPiper
sudo incus_manager
```

### 4. Configure SSH (Required)

See the [SSHPiper Manual Setup](#%EF%B8%8F-required-sshpiper-manual-setup-after-first-run) section below.

### 5. Create Your First Container

```bash
sudo incus_manager
```

The creation wizard will guide you through:
1. Enter domain name
2. Select base image (Ubuntu or Debian)
3. Configure DNS (optional auto-creation via Cloudflare/deSEC)
4. Set app port
5. Provide SSH public key
6. Set credentials
7. Choose LLM provider and enter API key

### Auto-installed Dependencies

The first run automatically installs:
- **Incus 6.20+** from Zabbly stable repository
- **Caddy** web server with automatic HTTPS
- **SSHPiper** SSH routing proxy

### What Gets Installed in Each Container

During container creation, the following is automatically installed:
- **Docker** (via official get.docker.com script)
- **Go** (latest version, architecture auto-detected)
- **Node.js** (latest LTS via NodeSource)
- **shelley-cli** (built from source)
- **API key configuration** (in user's ~/.bashrc)

## ⚠️ Required: SSHPiper Manual Setup (After First Run)

**Before creating containers**, verify SSHPiper is running:

```bash
# Check SSHPiper status (should be active)
sudo systemctl status sshpiperd

# If not running, start it
sudo systemctl enable --now sshpiperd
```

SSHPiper listens on **port 2222** for container SSH access. Host SSH remains on port 22.

### Verify Security Settings

Ensure your host SSH is properly secured in `/etc/ssh/sshd_config`:

```bash
PermitRootLogin no
PasswordAuthentication no
```

> **Security Note**: Always use a regular user account with sudo privileges for host
> administration. Never enable root login or password authentication on a public server.

## Usage

```bash
sudo incus_manager
```

### Key Bindings

**List View:**
- `n` - Create new container
- `Enter` - View container details
- `d` - Delete container
- `u` - Show untracked containers (import existing)
- `D` - Manage DNS API tokens (Cloudflare/deSEC)
- `i` - View Incus logs
- `l` - View sync daemon logs
- `q` - Quit

**Detail View:**
- `s` - Start/Stop container
- `r` - Restart container
- `p` - Change app port
- `a` - Change auth credentials
- `S` - Snapshot management
- `u` - Update shelley-cli
- `Esc` - Back to list

**Snapshot View:**
- `n` - Create new snapshot
- `Enter/r` - Restore selected snapshot
- `d` - Delete selected snapshot
- `↑/↓` or `j/k` - Navigate snapshots
- `Esc` - Back to container details

## Features

### Container Management
- **Native Incus Images**: Choose Ubuntu 24.04 LTS or Debian 12
- **Persistent Sandboxes**: Full filesystem persistence across restarts
- **Boot Behavior**: Containers respect their last state on host reboot
- **Resource Monitoring**: Live CPU and memory usage in TUI
- **Untracked Import**: Detect and adopt existing Incus containers
- **Snapshots**: Create, restore, and delete container snapshots

### Networking & Access
- **Automatic HTTPS**: Caddy handles Let's Encrypt certificates
- **Reverse Proxy**: Each container gets `https://domain.com` → Container's app (port 8000, configurable)
- **SSH Routing**: SSHPiper on port 2222 enables `ssh -p 2222 container-name@host` access
- **Auto DNS**: Cloudflare and deSEC API integration (tokens saved securely for reuse)

### shelley-cli Integration
- **Multiple LLM Providers**: Anthropic, OpenAI, Fireworks
- **Custom Endpoints**: Support for Azure OpenAI, local models, or proxies
- **Pre-configured**: API keys are set up during container creation
- **Full System Access**: shelley-cli runs with full container access

## Using shelley-cli

After creating a container, you can access shelley-cli in two ways:

### Web UI

Access the web interface at `https://shelley.yourdomain.com` (protected by HTTP Basic Auth with the credentials you set during creation).

### Terminal

SSH in and run shelley-cli:

```bash
# SSH to your container
ssh -p 2222 container-name@host.example.com

# Run shelley-cli
shelley
```

The API key you provided during container creation is already configured in `~/.bashrc`.

### Updating shelley-cli

From the container detail view, press `u` to update shelley-cli to the latest version. This will pull and rebuild from the repository.

### Using Custom API Endpoints

If you need to use a custom API endpoint (e.g., Azure OpenAI), you can provide a base URL during container creation. The base URL environment variables are:

- `ANTHROPIC_BASE_URL` - For Anthropic/Claude
- `OPENAI_BASE_URL` - For OpenAI/GPT
- `FIREWORKS_BASE_URL` - For Fireworks

## Snapshots

Snapshots allow you to save and restore the complete state of a container.

### Creating Snapshots

From the container detail view, press `S` to access snapshot management, then `n` to create.

### Use Cases

- **Before risky changes**: Snapshot before major updates or experiments
- **Known-good states**: Save working configurations you can restore to
- **Quick rollback**: Instantly revert if something breaks

> **Note**: Snapshots are stored by Incus and consume disk space. Delete old snapshots to free space.

## SSH Access

### To containers (via SSHPiper on port 2222):
```bash
ssh -p 2222 container-name@host.example.com
# You'll be logged in as 'ubuntu' (or 'debian') with sudo access
```

### To host (standard SSH on port 22):
```bash
ssh user@host.example.com
```

## DNS Configuration

For HTTPS to work, DNS must point to the host server:
- `domain.com` → Host IP
- `shelley.domain.com` → Host IP (for shelley-cli web UI)

Caddy will automatically obtain Let's Encrypt certificates for both domains.

## Architecture

```
                              Internet
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
              HTTPS (:443)         SSH (:2222 via SSHPiper)
                    │                         │
┌───────────────────▼─────────────────────▼─────────────────┐
│                         Host System                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐           ┌─────────────┐                    │
│  │    Caddy    │           │  SSHPiper   │                    │
│  │  (reverse   │           │  (SSH       │                    │
│  │   proxy)    │           │   router)   │                    │
│  └──────┬──────┘           └──────┬──────┘                    │
│         │                         │                           │
│         │    Routes by domain     │    Routes by username     │
│         ▼                         ▼                           │
│  ┌─────────────────────────────────────────────────────┐     │
│  │                    Incus (LXC)                       │     │
│  │                                                      │     │
│  │  ┌─────────────────┐  ┌─────────────────┐              │     │
│  │  │ Container      │  │ Container      │    ...       │     │
│  │  │ (Ubuntu/Debian)│  │ (Ubuntu/Debian)│              │     │
│  │  │                │  │                │              │     │
│  │  │  ┌───────────┐ │  │  ┌───────────┐ │              │     │
│  │  │  │shelley-cli│ │  │  │shelley-cli│ │              │     │
│  │  │  │  (term)   │ │  │  │  (term)   │ │              │     │
│  │  │  └───────────┘ │  │  └───────────┘ │              │     │
│  │  │  ┌───────────┐ │  │  ┌───────────┐ │              │     │
│  │  │  │ Your App  │ │  │  │ Your App  │ │              │     │
│  │  │  │  (:8000)  │ │  │  │  (:8000)  │ │              │     │
│  │  │  └───────────┘ │  │  └───────────┘ │              │     │
│  │  └─────────────────┘  └─────────────────┘              │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                               │
│  ┌───────────────────┐                                        │
│  │  incus_manager   │  TUI for container management            │
│  │  (this tool)     │  - Create/delete containers              │
│  │                  │  - Configure domains & auth              │
│  └───────────────────┘                                         │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### How Traffic Flows

1. **HTTPS requests** to `myapp.example.com` → Caddy → Container's app (port 8000)
2. **HTTPS requests** to `shelley.myapp.example.com` → Caddy (with Basic Auth) → shelley-cli web UI (port 9999)
3. **SSH connections** to port 2222 as `myapp-example-com@host` → SSHPiper → Container's SSH as `ubuntu`/`debian`

### Caddy Configuration

Routes are managed via Caddy's Admin API (localhost:2019), not config files:
- Routes use `@id` for identification (e.g., `container-name-app`)
- Changes are atomic and immediate (no reload required)
- Query current routes: `curl http://localhost:2019/config/apps/http/servers/srv0/routes`

## Known Issues / What Doesn't Work Currently

### Container Setup Time

Initial container creation takes several minutes as it installs Docker, Go, Node.js, and shelley-cli. This is a one-time setup per container.

### Other Limitations

- **IPv4 only**: IPv6 addresses not currently handled
- **Single host**: No clustering support (single Incus host only)
- **Two-part TLDs**: Domains like `.co.uk` need manual DNS setup (see below)

## Roadmap

### Storage Driver Selection

Currently, this implementation uses the **Incus DIR storage driver** for proof of concept. The DIR driver uses basic filesystem-level storage and is:
- Simple to set up (no additional dependencies)
- Compatible with any filesystem
- **Slow for snapshots** (full copy-on-write not available)

**Planned**: During the dependencies/installation phase, users will be able to choose between:

| Driver | Pros | Cons |
|--------|------|------|
| **DIR** | Simple, works everywhere | Slow snapshots, no CoW |
| **Btrfs** | Fast snapshots, CoW, compression | Requires Btrfs filesystem |
| **ZFS** | Fast snapshots, CoW, excellent features | Requires significant RAM (1GB+ per TB of storage) |

Btrfs and ZFS provide instant snapshots via copy-on-write, making them much more suitable for production use.

### Enhanced Authentication

We plan to evaluate [caddy-security](https://github.com/greenpau/caddy-security) for more advanced authentication options including:
- OAuth2/OIDC integration
- Multi-factor authentication
- Session management
- API key authentication

## Troubleshooting

**Container won't start:**
```bash
journalctl -u incus -f
incus info container-name
```

**Caddy certificate errors:**
- Ensure DNS is configured and pointing to host IP before creating container
- Check Caddy logs: `journalctl -u caddy -f`
- Check current routes: `curl -s http://localhost:2019/config/apps/http/servers/srv0/routes | jq .`

**SSH to containers not working:**
- Verify SSHPiper is running: `systemctl status sshpiperd`
- Ensure you're using port 2222: `ssh -p 2222 container-name@host`
- Verify upstream config: `cat /var/lib/sshpiper/container-name/sshpiper_upstream`

**shelley-cli not working:**
- Check if API key is set: `ssh -p 2222 container-name@host 'echo $ANTHROPIC_API_KEY'`
- Verify shelley-cli is installed: `ssh -p 2222 container-name@host 'which shelley'`

**Sync daemon issues:**
```bash
journalctl -u incus-sync -f
```

## Subdomain Support

You can use subdomains for your containers:
- `app.example.com` - works correctly
- `staging.app.example.com` - works correctly
- `my-app.example.com` - works correctly

### Limitation: Two-Part TLDs

Domains with two-part TLDs (like `.co.uk`, `.com.au`) are **not fully supported** 
for automatic DNS creation. The zone detection assumes a single-part TLD.

For example:
- ✅ `app.example.com` → zone: `example.com` (correct)
- ❌ `app.example.co.uk` → zone: `co.uk` (incorrect, should be `example.co.uk`)

**Workaround**: For two-part TLDs, select "No" for auto DNS creation and 
configure DNS records manually.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

### Third-Party Components

- **shelley-cli**: Fork of [boldsoftware/shelley-cli](https://github.com/boldsoftware/shelley-cli) - Apache 2.0 License
- **Incus**: [linuxcontainers/incus](https://github.com/lxc/incus) - Apache 2.0 License
- **Caddy**: [caddyserver/caddy](https://github.com/caddyserver/caddy) - Apache 2.0 License
- **SSHPiper**: [tg123/sshpiper](https://github.com/tg123/sshpiper) - MIT License
