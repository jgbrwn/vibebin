# Shelley-lxc | Incus Container Manager

A self-hosted platform for running persistent, web-accessible development sandboxes powered by [Shelley](https://github.com/boldsoftware/shelley) AI coding agents.

## What is this?

This project provides the infrastructure to self-host your own [exe.dev](https://exe.dev)-like environment. Each container is a fully persistent Linux sandbox running the **exeuntu** OCI image (the same image used by exe.dev), with:

- **Shelley web agent** accessible via HTTPS at `shelley.yourdomain.com`
- **Your app/site** accessible via HTTPS at `yourdomain.com`
- **SSH access** for direct terminal access to your sandbox
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
| **Caddy** | Reverse proxy with automatic HTTPS (Let's Encrypt) |
| **SSHPiper** | SSH routing - access any container via `ssh container-name@host` |
| **exeuntu** | OCI base image with development tools pre-installed |
| **Shelley** | AI coding agent running inside each container |

## Components

- `incus_manager` - Interactive TUI for container management
- `incus_sync_daemon` - Background service for config synchronization

## Prerequisites

- Ubuntu 22.04+ or Debian 12+ (amd64 or arm64)
- A domain name with DNS you control
- Root/sudo access

## Quick Start

```bash
# 1. Build the tools
go build -o incus_manager incus_manager.go
go build -o incus_sync_daemon incus_sync_daemon.go

# 2. Install (as root)
sudo cp incus_manager incus_sync_daemon /usr/local/bin/

# 3. Run first-time setup (auto-installs dependencies)
sudo incus_manager

# 4. Configure SSH (see below) - REQUIRED before creating containers

# 5. Create your first container!
sudo incus_manager
```

### Auto-installed Dependencies

The first run automatically installs:
- **Incus 6.20+** from Zabbly stable repository (with OCI image support)
- **Caddy** web server with automatic HTTPS
- **SSHPiper** SSH routing proxy

## ⚠️ Required: SSHPiper Manual Setup (After First Run)

**Before creating containers**, you must configure the host SSH to work with SSHPiper:

1. **Move host SSH to port 2222:**
   ```bash
   # Edit /etc/ssh/sshd_config and change:
   Port 2222
   
   # Restart SSH
   sudo systemctl restart sshd
   ```

2. **Start SSHPiper:**
   ```bash
   sudo systemctl enable --now sshpiperd
   ```

3. **Test host access (new port):**
   ```bash
   ssh -p 2222 user@host.example.com
   ```

> **Important**: After this setup, SSH to your host uses port 2222. Port 22 is now
> handled by SSHPiper for routing to containers.

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
- `i` - View Incus logs
- `l` - View sync daemon logs
- `q` - Quit

**Detail View:**
- `s` - Start/Stop container
- `r` - Restart container
- `p` - Change app port
- `a` - Change Shelley auth (username/password)
- `u` - Update Shelley binary on container
- `Esc` - Back to list

## Features

### Container Management
- **OCI Image Support**: Uses `ghcr.io/boldsoftware/exeuntu:latest` (exe.dev's base image)
- **Persistent Sandboxes**: Full filesystem persistence across restarts
- **Boot Behavior**: Containers respect their last state on host reboot
- **Resource Monitoring**: Live CPU and memory usage in TUI
- **Untracked Import**: Detect and adopt existing Incus containers

### Networking & Access
- **Automatic HTTPS**: Caddy handles Let's Encrypt certificates
- **Reverse Proxy**: Each container gets two endpoints:
  - `https://domain.com` → Your app (port 8000, configurable)
  - `https://shelley.domain.com` → Shelley web agent (port 9999)
- **SSH Routing**: SSHPiper enables `ssh container-name@host` access
- **Auto DNS**: Cloudflare and deSEC API integration

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

## SSH Access

### To containers:
```bash
ssh container-name@host.example.com
# You'll be logged in as 'exedev' with sudo access
```

### To host:
```bash
ssh -p 2222 user@host.example.com
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
              HTTPS (:443)              SSH (:22)
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
3. **SSH connections** as `myapp-example-com@host` → SSHPiper → Container's SSH as `exedev`

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

Containers are created with `boot.autostart=last-state`, which means:
- Running containers will restart when the host reboots
- Stopped containers will stay stopped

The `incus-startup.service` handles this at system boot.

## Limitations & Known Issues

- **IPv4 only**: IPv6 addresses not currently handled
- **DNS tokens not stored**: Re-enter if you need to update DNS records
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

**SSH not working:**
- Verify SSHPiper is running: `systemctl status sshpiperd`
- Check host SSH moved to port 2222
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
