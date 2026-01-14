# shelley-lxc | Incus Container Manager

An Incus/LXC-based platform for self-hosting persistent [Shelley](https://github.com/boldsoftware/shelley) web-based AI coding agent sandboxes with Caddy reverse proxy and direct SSH routing to a container (suitable for VS Code remote ssh).

Create and host your vibe-coded apps on a single VPS/server.

## *UPFRONT DISCLOSURE*

This project is 99.9% vibe-coded on the [exe.dev](https://exe.dev/docs/list) platform using their Shelley Web AI Coding Agent and Claude Opus 4.5.
Take that as you will.

With that said, I am a huge proponent of the exe.dev platform, and if you can, you should definitely try it out and use their service.  The love and care for that project/service is extremely evident... AND it is incredibly awesome (and I think it's in its infancy stages, so should only get better).

## *WARNING*

This is extremely alpha software and a very new project.  Feel free to test and experiment but it's likely to have bugs and definitely not ready for production.  Use at your own risk.

## What is this?

This project provides the infrastructure to self-host your own [exe.dev](https://exe.dev/docs/list)-like environment on virtually any Linux server -- a VPS, cloud VM (EC2, GCP, Azure), or dedicated hardware. Because it uses **Incus/LXC** (container-based virtualization rather than nested VMs), it runs efficiently on KVM, VMware, Xen, Hyper-V, and most other hypervisors.

Each container is a fully persistent Linux sandbox running the **exeuntu** OCI image (the same image used by exe.dev), with:

- **Shelley web agent** accessible via HTTPS at `shelley.yourdomain.com` (protected by Caddy Basic Auth)
- **Your app/site** accessible via HTTPS at `yourdomain.com`
- **SSH access** for direct terminal access to your sandbox (suitable for VS Code (and forks) remote ssh)
- **Persistent filesystem** that survives container restarts

### Use Cases

- **AI-assisted development**: Use Shelley as your AI pair programmer with full system access
- **Vibe coding**: Spin up isolated sandboxes for experimental projects
- **App/site hosting**: Deploy and iterate on web applications
- **Learning environments**: Safe, isolated Linux environments for experimentation
- **CI/CD sandboxes**: Temporary or persistent build environments

### Stack Overview

| Component | Purpose |
|-----------|--------|
| **Incus (LXC)** | Container runtime - lightweight, persistent Linux containers |
| **Caddy** | Reverse proxy with automatic HTTPS (Let's Encrypt with ZeroSSL fallback) |
| **SSHPiper** | SSH routing - access any container via `ssh -p 2222 container-name@host` |
| **exeuntu** | OCI base image (maintained by exe.dev team) with development tools pre-installed |
| **Shelley** | AI coding agent running inside each container |

## Components

- `incus_manager` - Interactive TUI for container management
- `incus_sync_daemon` - Background service for config synchronization

## Prerequisites

- **Fresh/minimal Linux installation**: Ubuntu 22.04+ or Debian 12+ (amd64 or arm64)
- **VPS or VM**: Works on most virtualization platforms (KVM, VMware, Xen, EC2, GCP, Azure, etc.)
- **Go 1.21+**: Required to build the tools (see Quick Start for installation)
- **A domain name** with DNS you control
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

### Auto-installed Dependencies

The first run automatically installs:
- **Incus 6.20+** from Zabbly stable repository (with OCI image support)
- **Caddy** web server with automatic HTTPS
- **SSHPiper** SSH routing proxy

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
- `a` - Change Shelley auth (username/password)
- `S` - Snapshot management
- `u` - Update Shelley binary on container
- `Esc` - Back to list

**Snapshot View:**
- `n` - Create new snapshot
- `Enter/r` - Restore selected snapshot
- `d` - Delete selected snapshot
- `↑/↓` or `j/k` - Navigate snapshots
- `Esc` - Back to container details

## Features

### Container Management
- **OCI Image Support**: Uses `ghcr.io/boldsoftware/exeuntu:latest` (exe.dev's base image)
- **Persistent Sandboxes**: Full filesystem persistence across restarts
- **Boot Behavior**: Containers respect their last state on host reboot
- **Resource Monitoring**: Live CPU and memory usage in TUI
- **Untracked Import**: Detect and adopt existing Incus containers
- **Snapshots**: Create, restore, and delete container snapshots

### Networking & Access
- **Automatic HTTPS**: Caddy handles Let's Encrypt certificates
- **Reverse Proxy**: Each container gets two endpoints:
  - `https://domain.com` → Your app (port 8000, configurable)
  - `https://shelley.domain.com` → Shelley web agent (port 9999)
- **SSH Routing**: SSHPiper on port 2222 enables `ssh -p 2222 container-name@host` access
- **Auto DNS**: Cloudflare and deSEC API integration (tokens saved securely for reuse)

### Security
- **Shelley Authentication**: HTTP Basic Auth protects the Shelley web interface
  - Username/password set during container creation
  - Credentials can be changed anytime
  - Passwords stored as bcrypt hashes
- **Isolated Containers**: Each sandbox is an isolated LXC container

### Shelley Integration
- **Update Shelley**: One-click update of Shelley binary on any container
- **Web Agent**: Access Shelley at `https://shelley.yourdomain.com`
- **Full System Access**: Shelley runs with full container access as `exedev` user

## Snapshots

Snapshots allow you to save and restore the complete state of a container.

### Creating Snapshots

From the container detail view, press `S` to access snapshot management, then `n` to create:

```
📸 SNAPSHOTS: my-container
═══════════════════════════════════════════════════════════════════════════════

[n] New  [Enter/r] Restore  [d] Delete  [Esc] Back

  NAME                            CREATED               STATEFUL
  ────────────────────────────────────────────────────────────────
▶ snap-20260113-150000            2026-01-13 15:00:00   no
  before-upgrade                  2026-01-12 10:30:00   no
```

### Use Cases

- **Before risky changes**: Snapshot before major updates or experiments
- **Known-good states**: Save working configurations you can restore to
- **Quick rollback**: Instantly revert if something breaks

### How It Works

- **Create**: Captures the entire container filesystem state
- **Restore**: Stops the container, restores the snapshot, then restarts
- **Delete**: Removes the snapshot (does not affect the running container)

> **Note**: Snapshots are stored by Incus and consume disk space. Delete old snapshots to free space.

## SSH Access

### To containers (via SSHPiper on port 2222):
```bash
ssh -p 2222 container-name@host.example.com
# You'll be logged in as 'exedev' with sudo access
```

### To host (standard SSH on port 22):
```bash
ssh user@host.example.com
```

## DNS Configuration

For HTTPS to work, DNS must point to the host server:
- `domain.com` → Host IP
- `shelley.domain.com` → Host IP

Caddy will automatically obtain Let's Encrypt certificates.

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
│  │  │ (exeuntu)      │  │ (exeuntu)      │              │     │
│  │  │                │  │                │              │     │
│  │  │  ┌───────────┐ │  │  ┌───────────┐ │              │     │
│  │  │  │  Shelley  │ │  │  │  Shelley  │ │              │     │
│  │  │  │  (:9999)  │ │  │  │  (:9999)  │ │              │     │
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
│  └───────────────────┘  - Update Shelley                        │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### How Traffic Flows

1. **HTTPS requests** to `myapp.example.com` → Caddy → Container's app (port 8000)
2. **HTTPS requests** to `shelley.myapp.example.com` → Caddy (with auth) → Container's Shelley (port 9999)
3. **SSH connections** to port 2222 as `myapp-example-com@host` → SSHPiper → Container's SSH as `exedev`

### Caddy Configuration

Routes are managed via Caddy's Admin API (localhost:2019), not config files:
- Routes use `@id` for identification (e.g., `container-name-app`, `container-name-shelley`)
- Changes are atomic and immediate (no reload required)
- Query current routes: `curl http://localhost:2019/config/apps/http/servers/srv0/routes`

## Technical Details

### Incus API Usage

The tool uses the Incus API (via `incus query` and JSON-formatted commands) as the source of truth for container state. The database stores association metadata (domain, app port) while Incus remains authoritative for:
- Container existence and status
- IP addresses
- Resource usage (CPU, memory)

### Container Boot Behavior

Containers use Incus's default "last-state" behavior (by not setting `boot.autostart`):
- Running containers will restart when the host reboots
- Stopped containers will stay stopped

Incus automatically tracks each container's power state and restores it when the daemon starts.

## Limitations & Known Issues

- **IPv4 only**: IPv6 addresses not currently handled
- **Single host**: No clustering support (single Incus host only)
- **Two-part TLDs**: Domains like `.co.uk` need manual DNS setup (see below)

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

**Sync daemon issues:**
```bash
journalctl -u incus-sync -f
```

## Subdomain Support

You can use subdomains for your containers:
- `app.example.com` - works correctly
- `staging.app.example.com` - works correctly
- `my-app.example.com` - works correctly

The shelley agent will be available at `shelley.<your-domain>`:
- Domain: `app.example.com` → Shelley: `shelley.app.example.com`

### Limitation: Two-Part TLDs

Domains with two-part TLDs (like `.co.uk`, `.com.au`) are **not fully supported** 
for automatic DNS creation. The zone detection assumes a single-part TLD.

For example:
- ✅ `app.example.com` → zone: `example.com` (correct)
- ❌ `app.example.co.uk` → zone: `co.uk` (incorrect, should be `example.co.uk`)

**Workaround**: For two-part TLDs, select "No" for auto DNS creation and 
configure DNS records manually.
