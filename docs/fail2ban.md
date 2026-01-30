# Fail2ban Installation & Configuration for Vibebin

> **Note:** Fail2ban should be installed and configured **AFTER** the initial vibebin run so that Caddy and SSHPiper are already in place.

## Installation

```bash
sudo apt update && sudo apt install -y fail2ban python3-systemd
```

## Configuration Files

Create the following configuration files:

### Caddy Flood Filter

`/etc/fail2ban/filter.d/caddy-flood.conf`

```ini
[Definition]
# Matches the client IP in Caddy's JSON logs
failregex = ^.*"remote_ip":"<HOST>".*$
ignoreregex =
```

### SSHPiper Filter

`/etc/fail2ban/filter.d/sshpiper.conf`

```ini
[Definition]
# Matches logs from the sshpiperd service in journalctl
journalmatch = _SYSTEMD_UNIT=sshpiperd.service

# Regex for the "cannot create upstream" error format
# Captures the IP address before the colon and port number
failregex = ^.*level=error msg="cannot create upstream for <HOST>:\d+.*$

ignoreregex =
```

### Jail Configuration

`/etc/fail2ban/jail.local`

```ini
# Vibebin fail2ban configuration
# Ignores localhost and container network traffic
# Note: Some ban times are intentionally aggressive

[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 10.128.31.0/24 fd42:ace5:c1f4:81db::/64

# If not using UFW firewall then comment this out
banaction = ufw
banaction_allports = ufw

[caddy-flood]
enabled = true
port = http,https
filter = caddy-flood
logpath = /var/log/caddy/access.log

# 100 requests (maxretry) within 30 seconds (findtime) triggers the ban
findtime = 30s
maxretry = 100

# Ban duration (12 hrs)
bantime = 12h

# Incremental banning (doubles ban time on repeat offenses)
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 52w

[sshpiperd]
enabled  = true
port     = 2222
filter   = sshpiper
backend  = systemd
maxretry = 3
findtime = 10m
bantime  = 12h

# Incremental banning (doubles ban time on repeat offenses)
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 52w
```

> **Note:** Adjust the `ignoreip` values to match your Incus bridge network. You can find your network ranges with:
> ```bash
> incus network show incusbr0 | grep -E 'ipv4.address|ipv6.address'
> ```

## Activate Configuration

```bash
# Create the Caddy access log file if it doesn't exist yet
# (It may not be created until after the first container is created in Vibebin)
sudo touch /var/log/caddy/access.log

sudo systemctl restart fail2ban
```

## Verify Status

```bash
# Check fail2ban status
sudo fail2ban-client status

# Check specific jail status
sudo fail2ban-client status sshd          # Host SSH (default jail)
sudo fail2ban-client status caddy-flood   # Caddy flood protection
sudo fail2ban-client status sshpiperd     # SSHPiper protection

# View banned IPs
sudo fail2ban-client get sshd banned
sudo fail2ban-client get caddy-flood banned
sudo fail2ban-client get sshpiperd banned
```

## Unban an IP

```bash
# Unban from specific jail
sudo fail2ban-client set caddy-flood unbanip <IP_ADDRESS>
sudo fail2ban-client set sshpiperd unbanip <IP_ADDRESS>
```

## Troubleshooting

### Test Filter Regex

```bash
# Test caddy filter against log file
sudo fail2ban-regex /var/log/caddy/access.log /etc/fail2ban/filter.d/caddy-flood.conf

# Test sshpiper filter against journald
sudo fail2ban-regex systemd-journal /etc/fail2ban/filter.d/sshpiper.conf
```

### View Fail2ban Logs

```bash
sudo tail -f /var/log/fail2ban.log
```
