# Incus Container Manager

A TUI application for managing Incus LXC containers with automatic Caddy reverse proxy and SSHPiper configuration.

## Components

- `incus_manager` - Interactive TUI for container management
- `incus_sync_daemon` - Background service for config synchronization

## Installation

```bash
# Build
go build -o incus_manager incus_manager.go
go build -o incus_sync_daemon incus_sync_daemon.go

# Install (as root)
cp incus_manager /usr/local/bin/
cp incus_sync_daemon /usr/local/bin/

# Run incus_manager to auto-install dependencies
sudo incus_manager
```

The first run will automatically install:
- Incus 6.20+ from Zabbly stable repository (OCI support)
- Caddy web server
- SSHPiper SSH proxy

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
- `Esc` - Back to list

## Features

- **OCI Image Support**: Uses `ghcr.io/boldsoftware/exeuntu:latest`
- **Auto DNS**: Cloudflare and deSEC API integration (idempotent - safe to re-run)
  - Cloudflare: Option to enable/disable proxy (defaults to DNS-only)
- **Reverse Proxy**: Caddy auto-configured via Admin API (localhost:2019)
  - `https://domain.com` → container:8000 (configurable)
  - `https://shelley.domain.com` → container:9999 (protected by auth)
- **Shelley Authentication**: Basic auth protects Shelley URLs
  - Username/password set during container creation
  - Uses Caddy's built-in HTTP basic authentication
  - Password stored as bcrypt hash
- **SSH Access**: SSHPiper routes SSH by container name to `exedev` user
- **State Preservation**: Container state (filesystem, etc.) preserved across reboots
- **Boot Behavior**: Containers respect their last state on host reboot (running→running, stopped→stopped)
- **Resource Monitoring**: CPU and memory usage displayed
- **Untracked Container Import**: Detect and import containers not created by incus_manager

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
┌─────────────────────────────────────────────────────────────┐
│                        Host System                          │
├─────────────────────────────────────────────────────────────┤
│  incus_manager (TUI)     incus_sync_daemon (background)    │
│         │                         │                         │
│         ▼                         ▼                         │
│  ┌─────────────┐         ┌──────────────────┐              │
│  │   SQLite    │         │  incus monitor   │              │
│  │  Database   │         │  (lifecycle)     │              │
│  └─────────────┘         └──────────────────┘              │
│         │                         │                         │
│         ▼                         ▼                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Incus Daemon                      │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐       │   │
│  │  │Container 1│  │Container 2│  │Container 3│       │   │
│  │  │ :8000     │  │ :8000     │  │ :8000     │       │   │
│  │  │ :9999     │  │ :9999     │  │ :9999     │       │   │
│  │  └───────────┘  └───────────┘  └───────────┘       │   │
│  └─────────────────────────────────────────────────────┘   │
│         ▲                         ▲                         │
│         │   Caddy Admin API       │                         │
│         │   (localhost:2019)      │                         │
│  ┌──────┴──────┐           ┌──────┴──────┐                 │
│  │    Caddy    │           │  SSHPiper   │                 │
│  │   :80/443   │           │    :22      │                 │
│  └─────────────┘           └─────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                    │                   │
                    ▼                   ▼
              HTTPS Traffic        SSH Traffic
```

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

## Limitations

- **IPv4 only**: IPv6 addresses not currently handled
- **DNS updates**: DNS tokens not stored; manual update needed if IP changes

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
