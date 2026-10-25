# tarpit

universal multi-protocol network tarpit (FreeBSD)

(c) 2026 Lukasz Bromirski, Qwen3.5, gemma4 and Claude.AI

Accepts connections from brute-force scanners, completes TLS handshakes where required, then responds as slowly as possible — wasting attacker CPU, threads, and file descriptors.

Inspired by [endlessh](https://github.com/skeeto/endlessh) but generalised to any TCP protocol, with TLS support, TOML configuration, and syslog integration.

## Build

```sh
# Install Rust toolchain (one of):
pkg install rust                         # binary package, fastest

cd tarpit
cargo build --release
strip target/release/tarpit
sudo cp target/release/tarpit /usr/local/bin/tarpit
```

## Setup

### 1. Create unprivileged user

```sh
sudo pw groupadd tarpit -g 5999
sudo pw useradd tarpit -u 5999 -g tarpit -d /nonexistent -s /usr/sbin/nologin -c "Network tarpit daemon"
```

### 2. Create local TLS certificate

```sh
sudo mkdir -p /usr/local/etc/tarpit
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout /usr/local/etc/tarpit/key.pem -out /usr/local/etc/tarpit/cert.pem \
    -days 3650 -nodes -subj '/CN=server.example.com'
sudo chmod 640 /usr/local/etc/tarpit/key.pem
sudo chown root:tarpit /usr/local/etc/tarpit/key.pem
```

### 3. Install configuration

```sh
sudo mkdir -p /usr/local/etc/tarpit
sudo cp tarpit.toml /usr/local/etc/tarpit/tarpit.toml
```

Edit `/usr/local/etc/tarpit/tarpit.toml` to match your environment. Validate before starting:

```sh
tarpit --config /usr/local/etc/tarpit/tarpit.toml --check
```

### 4. Configure pf(4) redirection

`pf` must be enabled before the redirects take effect.

```sh
# /etc/rc.conf additions:
sudo sysrc pf_enable="YES"
sudo sysrc pflog_enable="YES"       # optional - packet logging

# Merge pf.conf.example rules into /etc/pf.conf
# IMPORTANT: edit <tarpit_bypass> table with your management IPs first!
sudo vi /etc/pf.conf

# Syntax check, then load:
sudo pfctl -n -f /etc/pf.conf       # dry run - must show no errors
sudo pfctl -e -f /etc/pf.conf       # enable pf and load rules
# or if pf is already running:
sudo pfctl -f /etc/pf.conf

# Verify redirects are in place:
sudo pfctl -s nat
```

**Critical**: add your management IP to the `<tarpit_bypass>` table in `pf.conf.example` **before** loading the rules, or you will redirect your own SSH session into the tarpit.

Runtime table management (no rule reload needed):

```sh
# Add an IP to the bypass table:
sudo pfctl -t tarpit_bypass -T add 203.0.113.5

# List bypass table:
sudo pfctl -t tarpit_bypass -T show
```

### 5. Install and start the rc.d service

```sh
sudo cp tarpit.rc.d /usr/local/etc/rc.d/tarpit
sudo chmod 555 /usr/local/etc/rc.d/tarpit

# Enable in /etc/rc.conf:
sudo sysrc tarpit_enable="YES"
sudo sysrc tarpit_user="tarpit"
sudo sysrc tarpit_config="/usr/local/etc/tarpit/tarpit.toml"

# Start:
sudo service tarpit start
sudo service tarpit status
```

Run in foreground for debugging (logs to stderr + syslog):
```sh
tarpit --config /usr/local/etc/tarpit/tarpit.toml --foreground
```

## Syslog output

Every completed session logs one structured line to syslog (facility `daemon`,
or as configured):

```
Jun 10 14:22:07 host tarpit[1234]: service=ssh src_ip=198.51.100.7 src_port=54321 duration_ms=3598241 reason=timeout
Jun 10 14:22:09 host tarpit[1234]: service=http src_ip=203.0.113.4 src_port=60001 duration_ms=12034 reason=client_disconnected
```

| Field | Meaning |
|-------|---------|
| `service` | Service name from config |
| `src_ip` | Scanner's source IP address |
| `src_port` | Scanner's source port |
| `duration_ms` | Milliseconds the connection was held |
| `reason` | `timeout` / `client_disconnected` / `io_error` |

On FreeBSD, syslog messages go to `/var/log/daemon.log` by default
(controlled by `/etc/syslog.conf`). To separate tarpit messages:

```
# /etc/syslog.conf addition:
!tarpit
*.*     /var/log/tarpit.log
```

Then `sudo touch /var/log/tarpit.log && sudo service syslogd reload`.

## Adding a new service

Add a `[[service]]` block to `tarpit.toml`, then add a matching `rdr` line to
`/etc/pf.conf` and reload pf:

```toml
[[service]]
name                    = "rdp"
bind_port               = 33389        # rdr :3389 → :33389
max_connections         = 256
connection_timeout_secs = 300
tarpit_mode             = "hold"       # RDP negotiation is binary; stay silent
tick_ms                 = 60000
jitter_ms               = 30000
```

```sh
# pf.conf addition:
# rdr pass on $ext_if proto tcp from !<tarpit_bypass> to any port 3389 -> $tarpit_addr port 33389

sudo pfctl -f /etc/pf.conf
sudo service tarpit restart
```

## Tarpit modes reference

| Mode | Sends | Best for |
|------|-------|----------|
| `lines` | Random printable-ASCII CR-LF lines | SSH (RFC 4253 pre-auth banner) |
| `static` | `static_data` byte-by-byte, cyclically | HTTP headers, SMTP greeting, IMAP |
| `hold` | Nothing - just holds the connection | Binary protocols (RDP, VNC, custom) |

## Security notes

- The tarpit runs as an **unprivileged user** (`tarpit`). No `CAP_NET_BIND_SERVICE` or `setuid` needed because pf handles the port redirect in kernel space.
- Received data is **never parsed** — it is read into a fixed 4096-byte stack buffer and discarded immediately. There is no path from attacker-controlled bytes to allocation decisions or format strings.
- `max_connections` per service prevents the tarpit from becoming a local resource exhaustion vector (memory proportional to open connections).
- The TLS handshake has its own configurable timeout (`handshake_timeout_secs`) independent of the overall `connection_timeout_secs`, preventing resource exhaustion by clients that initiate but never complete TLS.
- All Rust code is safe (zero `unsafe` in service/config/tls modules; only two `unsafe` calls in `slog.rs` for `libc::openlog` and `libc::syslog`, which have no memory-safe Rust equivalents).

## STARTTLS limitation

STARTTLS (port 587 SMTP submission, plain-text IMAP upgrade) requires a
protocol state machine: receive EHLO, respond, wait for STARTTLS, upgrade.
The current code does not implement this. Workaround: use `tarpit_mode = "static"`
with a plausible plaintext greeting on the relevant port — clients that skip
straight to STARTTLS will wait for the banner to complete.
