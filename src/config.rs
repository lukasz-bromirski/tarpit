// config.rs - TOML configuration structures for tarpit

use std::path::{Path, PathBuf};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Top-level
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,

    #[serde(default)]
    pub syslog: SyslogConfig,

    #[serde(default)]
    pub stats: StatsConfig,

    #[serde(rename = "service")]
    pub services: Vec<ServiceConfig>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read {:?}: {}", path, e))?;
        let cfg: Config = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parse error in {:?}: {}", path, e))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.services.is_empty() {
            anyhow::bail!("config: no [[service]] sections defined");
        }
        for s in &self.services {
            if s.bind_port == 0 {
                anyhow::bail!("service '{}': bind_port 0 is reserved", s.name);
            }
            if s.bind_addrs.is_empty() {
                anyhow::bail!("service '{}': bind_addrs must not be empty", s.name);
            }
            if s.max_connections == 0 {
                anyhow::bail!("service '{}': max_connections must be > 0", s.name);
            }
            if s.tick_ms == 0 {
                anyhow::bail!("service '{}': tick_ms must be > 0", s.name);
            }
            if let TarpitMode::Static = s.tarpit_mode {
                if s.static_data.is_empty() {
                    anyhow::bail!(
                        "service '{}': tarpit_mode = \"static\" requires static_data",
                        s.name
                    );
                }
                if s.bytes_per_tick == 0 {
                    anyhow::bail!("service '{}': bytes_per_tick must be > 0", s.name);
                }
            }
            if let TarpitMode::Lines = s.tarpit_mode {
                if s.line_min_len == 0 || s.line_max_len == 0 {
                    anyhow::bail!(
                        "service '{}': line_min_len and line_max_len must be > 0",
                        s.name
                    );
                }
                if s.line_min_len > s.line_max_len {
                    anyhow::bail!(
                        "service '{}': line_min_len ({}) > line_max_len ({})",
                        s.name, s.line_min_len, s.line_max_len
                    );
                }
            }
            if let TarpitMode::SshKex = s.tarpit_mode {
                // RFC 4253 §4.2: the server's identification string MUST begin
                // with "SSH-".  If we don't enforce this, the banner is
                // useless - the client never transitions out of the read-banner
                // phase and we hold them for at most first_tick_ms, not the
                // full KEX timeout.
                if !s.ssh_banner.starts_with("SSH-") {
                    anyhow::bail!(
                        "service '{}': tarpit_mode = \"ssh_kex\" requires \
                         ssh_banner to start with \"SSH-\" (per RFC 4253 §4.2); \
                         got: {:?}",
                        s.name, s.ssh_banner
                    );
                }
                // No \r\n in the configured banner - we append it.  Catching
                // this early prevents a doubled \r\n\r\n which some strict
                // SSH parsers reject.
                if s.ssh_banner.contains('\r') || s.ssh_banner.contains('\n') {
                    anyhow::bail!(
                        "service '{}': ssh_banner must not contain \\r or \\n; \
                         the terminator is appended by the daemon",
                        s.name
                    );
                }
            }
            if let TarpitMode::SmtpDrip = s.tarpit_mode {
                // smtp_banner_lines is clamped at runtime to [1, 20] but we
                // warn early so misconfiguration is loud rather than silent.
                if s.smtp_banner_lines == 0 || s.smtp_banner_lines > 20 {
                    anyhow::bail!(
                        "service '{}': smtp_banner_lines must be 1..=20; \
                         got {} (5 is the spamd-style default)",
                        s.name, s.smtp_banner_lines
                    );
                }
                // Hostname must not contain CRLF — it goes straight into
                // the 220 greeting and would break the SMTP framing.
                if s.hostname.contains('\r') || s.hostname.contains('\n') {
                    anyhow::bail!(
                        "service '{}': hostname must not contain \\r or \\n",
                        s.name
                    );
                }
            }
            if let Some(tls) = &s.tls {
                if !tls.cert_pem.exists() {
                    anyhow::bail!(
                        "service '{}': cert_pem {:?} not found",
                        s.name, tls.cert_pem
                    );
                }
                if !tls.key_pem.exists() {
                    anyhow::bail!(
                        "service '{}': key_pem {:?} not found",
                        s.name, tls.key_pem
                    );
                }
                if tls.handshake_timeout_secs == 0 {
                    anyhow::bail!(
                        "service '{}': handshake_timeout_secs must be > 0",
                        s.name
                    );
                }
            }

            // Validate every entry in bind_addrs is a bare IP address.
            // We check here so the error message is clear rather than a
            // cryptic bind(2) failure later.  Supply bare IPs only:
            // "127.0.0.1" or "::1", not "[::1]" or a hostname.
            for addr in &s.bind_addrs {
                if addr.parse::<std::net::IpAddr>().is_err() {
                    anyhow::bail!(
                        "service '{}': bind_addrs entry '{}' is not a valid IP address \
                         (use bare IPs such as '127.0.0.1' or '::1')",
                        s.name, addr
                    );
                }
            }
        }

        // Check for duplicate (bind_addr, port) pairs across all services
        // and within a single service's bind_addrs list.
        let mut seen = std::collections::HashSet::new();
        for s in &self.services {
            for addr in &s.bind_addrs {
                let key = (addr.clone(), s.bind_port);
                if !seen.insert(key.clone()) {
                    anyhow::bail!(
                        "service '{}': duplicate bind address {}:{}",
                        s.name, key.0, key.1
                    );
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// [daemon] section
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,

    #[serde(default = "default_working_dir")]
    pub working_dir: PathBuf,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pid_file:    default_pid_file(),
            working_dir: default_working_dir(),
        }
    }
}

fn default_pid_file()    -> PathBuf { PathBuf::from("/var/run/tarpit.pid") }
fn default_working_dir() -> PathBuf { PathBuf::from("/var/tmp") }

// ---------------------------------------------------------------------------
// [syslog] section
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct SyslogConfig {
    #[serde(default = "default_facility")]
    pub facility: String,

    #[serde(default = "default_level")]
    pub level: String,

    #[serde(default = "default_ident")]
    pub ident: String,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            facility: default_facility(),
            level:    default_level(),
            ident:    default_ident(),
        }
    }
}

fn default_facility() -> String { "daemon".into() }
fn default_level()    -> String { "info".into()   }
fn default_ident()    -> String { "tarpit".into()  }

// ---------------------------------------------------------------------------
// [stats] section
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct StatsConfig {
    /// Emit a summary report to syslog every this many seconds.
    /// Set to 0 to disable the reporter entirely.
    #[serde(default = "default_stats_interval")]
    pub interval_secs: u64,
}

impl Default for StatsConfig {
    fn default() -> Self { Self { interval_secs: default_stats_interval() } }
}

fn default_stats_interval() -> u64 { 3600 } // 60 minutes

// ---------------------------------------------------------------------------
// TLS sub-section (optional inside [[service]])
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_pem: PathBuf,
    pub key_pem:  PathBuf,

    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
}

fn default_handshake_timeout() -> u64 { 10 }

// ---------------------------------------------------------------------------
// [[service]] section
// ---------------------------------------------------------------------------

/// Controls what the tarpit sends during a session.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TarpitMode {
    /// Endlessh-style: drip random pre-banner lines forever.  Holds
    /// idle-timeout scanners indefinitely; loses hard-total-timeout
    /// scanners at their ceiling (~10 s for libssh2/Paramiko defaults).
    #[default]
    Lines,
    /// Cycle bytes through `static_data` at `bytes_per_tick` per send.
    /// Used for HTTP/SMTP masquerade replies.
    Static,
    /// Send no data; rely purely on a long `connection_timeout_secs`
    /// to hold the connection open.
    Hold,
    /// SSH-specific: send a single realistic-looking version banner
    /// (the `ssh_banner` field) within `first_tick_ms`, then stay silent
    /// for the rest of the session.  The client transitions into the
    /// SSH key-exchange state machine and waits for our KEXINIT - which
    /// never arrives - until its KEX timeout fires.  KEX timeouts in
    /// libssh2 / Paramiko / OpenSSH client are typically much longer
    /// than banner timeouts (30 s - 10 min), so this mode holds the
    /// hard-total-timeout cohort that `lines` cannot.
    SshKex,
    /// HTTP-specific: act like a slow HTTP/1.1 server.  Reads the request,
    /// drips a plausible status line and headers byte-by-byte, then opens
    /// a chunked-encoded HTML body and streams realistic-looking <head>
    /// and <body> content forever (one small chunk every `tick_ms`).
    /// Never sends the terminating chunk, so the client waits indefinitely
    /// for "more body".  Designed for ports 80/8080/443/8443.
    /// Uses: hostname, first_tick_ms, tick_ms, jitter_ms, bytes_per_tick.
    HttpDrip,
    /// SMTP-specific: engages with the SMTP command state machine.
    /// Drips the 220 banner, accepts EHLO with a long multi-line capability
    /// list, accepts MAIL FROM / RCPT TO slowly, accepts DATA, drains the
    /// message body without complaint, then returns 421 ("try again later")
    /// after a long delay - forcing the sender to re-queue and retry days
    /// later, only to repeat the whole thing.  Holds spam-cannon scanners
    /// for the full SMTP transaction window (often 60-300 s) instead of
    /// the few hundred ms they'd spend on a fast reject.  Open-relay safe:
    /// we never accept (250 OK after DATA), so nothing actually flows.
    /// Designed for port 25 (and 465/587 with TLS).
    /// Uses: hostname, first_tick_ms, tick_ms, bytes_per_tick.
    SmtpDrip,
    /// SSH adaptive: starts as ssh_kex (banner + KEX-sit), but tracks each
    /// source IP's recent disconnect pattern.  When an IP repeatedly
    /// disconnects in the 8-13 s window with io_error (the signature of a
    /// hard-total-timeout or post-banner-timeout scanner), subsequent
    /// connections from that IP switch to "lines" mode instead - on the
    /// theory that for some scanner cohorts the banner-phase timeout is
    /// longer than the KEX-phase timeout, and never sending a banner keeps
    /// them in the more lenient phase longer.
    ///
    /// Honest caveat: for scanners with a hard 10 s total-connect timeout
    /// (no per-phase distinction), this mode produces the same ~10 s as
    /// ssh_kex.  It only helps when banner-vs-KEX timeouts genuinely differ.
    /// Watch the logs to see which cohort you have.
    ///
    /// Uses: ssh_banner (for the ssh_kex sub-mode), and all "lines" fields
    /// (line_min_len, line_max_len, tick_ms, jitter_ms) for the fallback.
    SshAdaptive,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    /// Human-readable label; appears in every syslog line.
    pub name: String,

    /// High (unprivileged) port to listen on.
    pub bind_port: u16,

    /// IP addresses to bind to.  Defaults to ["127.0.0.1"] (IPv4 loopback only).
    ///
    /// For dual-stack hosts set:
    ///   bind_addrs = ["127.0.0.1", "::1"]
    ///
    /// Each entry must be a bare IP address - not a hostname, not "[::1]".
    /// One listener is spawned per address; max_connections applies to the
    /// service as a whole across all listeners.
    #[serde(default = "default_bind_addrs")]
    pub bind_addrs: Vec<String>,

    /// TLS configuration; if present connections are wrapped in TLS.
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Hard cap on simultaneous connections across all listeners for this service.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Drop a connection after this many seconds.
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,

    #[serde(default)]
    pub tarpit_mode: TarpitMode,

    /// Base interval between slow-drip events (milliseconds).
    #[serde(default = "default_tick_ms")]
    pub tick_ms: u64,

    /// Random jitter added to each tick (milliseconds).
    #[serde(default = "default_jitter_ms")]
    pub jitter_ms: u64,

    /// Delay before the very first send after a client connects (milliseconds).
    ///
    /// SSH, SMTP and IMAP are server-speaks-first protocols: the client connects
    /// and waits silently for the server banner before doing anything itself.
    /// Aggressive scanners have short banner timeouts (3-15 s).  If we wait the
    /// full tick_ms before sending anything, they fire their timeout and RST us.
    ///
    /// A short first_tick_ms (e.g. 500 ms) sends the first garbage bytes quickly
    /// enough that the scanner believes the server is live and waits for the rest
    /// of the banner - which never arrives - potentially for hours.
    ///
    /// HTTP/HTTPS are client-speaks-first: the scanner sends a request before we
    /// need to respond, so it is already committed.  first_tick_ms is less urgent
    /// for those services but still harmless to keep short.
    ///
    /// Set to 0 to send the first chunk immediately on accept (endlessh style).
    /// Default: 500 ms.
    #[serde(default = "default_first_tick_ms")]
    pub first_tick_ms: u64,

    #[serde(default = "default_line_min_len")]
    pub line_min_len: usize,

    #[serde(default = "default_line_max_len")]
    pub line_max_len: usize,

    #[serde(default)]
    pub static_data: String,

    #[serde(default = "default_bytes_per_tick")]
    pub bytes_per_tick: usize,

    /// Banner string sent when `tarpit_mode = "ssh_kex"`.
    ///
    /// MUST start with "SSH-" to satisfy RFC 4253 §4.2 and convince the client
    /// that the banner phase is complete.  The trailing "\r\n" is appended
    /// automatically by the daemon; do not include it here.
    ///
    /// install.sh substitutes the OpenSSH version portion with a randomised
    /// realistic version (8.x .. 10.x) at install time, so the per-host banner
    /// fingerprint is unique.  Ignored when tarpit_mode is not "ssh_kex".
    ///
    /// Default: SSH-2.0-OpenSSH_9.7
    #[serde(default = "default_ssh_banner")]
    pub ssh_banner: String,

    /// Hostname used by `http_drip` and `smtp_drip` modes to construct
    /// realistic protocol responses:
    ///   - SMTP greeting: "220 {hostname} ESMTP Postfix (FreeBSD)"
    ///   - HTTP Server header signature: "...Server at {hostname} Port 80"
    ///
    /// install.sh sed-substitutes "mail.example.com" with the actual system
    /// hostname at install time, so the default literal here is the placeholder
    /// that gets replaced.  Ignored by tarpit modes that don't use it.
    ///
    /// Default: "mail.example.com"
    #[serde(default = "default_hostname")]
    pub hostname: String,

    /// Number of lines in the SMTP/SMTPS multi-line 220 greeting (spamd
    /// style).  The first line is always the realistic Postfix banner;
    /// middle lines are random plausible service-notice strings from a
    /// built-in corpus; the last line is a short closer.  All lines are
    /// dripped byte-by-byte and separated by tick_ms pauses.
    ///
    /// With aggressive timing (bytes_per_tick=1, tick_ms=1000) this is
    /// where the bulk of the per-session time comes from: 5 lines x
    /// ~50 chars x 1 byte/sec ≈ 4-5 minutes of session burned before
    /// the spammer can even issue EHLO.
    ///
    /// Clamped to 1..=20.  Set to 1 to fall back to a single-line greeting.
    /// Default: 5 (matches spamd's default).  Only used by smtp_drip mode.
    #[serde(default = "default_smtp_banner_lines")]
    pub smtp_banner_lines: usize,
}

fn default_bind_addrs()         -> Vec<String> { vec!["127.0.0.1".into()] }
fn default_max_connections()    -> usize        { 4096  }
fn default_connection_timeout() -> u64          { 3600  }
fn default_tick_ms()            -> u64          { 10000 }
fn default_jitter_ms()          -> u64          { 5000  }
fn default_first_tick_ms()      -> u64          { 500   }
fn default_line_min_len()       -> usize        { 16    }
fn default_line_max_len()       -> usize        { 32    }
fn default_bytes_per_tick()     -> usize        { 1     }
fn default_ssh_banner()         -> String       { "SSH-2.0-OpenSSH_9.7".into() }
fn default_hostname()           -> String       { "mail.example.com".into() }
fn default_smtp_banner_lines()  -> usize        { 5     }
