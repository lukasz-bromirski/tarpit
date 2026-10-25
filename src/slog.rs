// slog.rs - thin façade over the `syslog` crate (https://lib.rs/crates/syslog).
//
// Why the syslog crate instead of libc::openlog/syslog():
//   - No unsafe code, no manual CString lifetime management.
//   - Type-safe Facility / Severity enums (compile-time checked).
//   - Proper Result types - we know when the AF_UNIX socket to syslogd
//     has gone away, instead of silently dropping messages.
//   - This is the path recommended by lib.rs and the broader Rust
//     ecosystem (the `log` crate ecosystem also routes through it
//     via syslog::BasicLogger if we ever want to adopt log!() macros).
//
// Trade-offs vs the previous libc::syslog wrapper:
//   - One small heap allocation per message (the crate formats into String).
//   - A Mutex protects the writer (the previous code relied on libc's
//     internal locking).  For a tarpit's log volume (a handful of messages
//     per connection event, not per packet) the mutex cost is invisible.
//   - If syslogd is not running when init() fires, init() returns Err.
//     Callers should treat this as fatal in foreground mode and as a
//     warning in daemon mode (we can still operate without logs).

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::OnceLock;

pub use syslog::{Facility, Severity};
use syslog::{Formatter3164, Logger, LoggerBackend};

// Global state.  OnceLock keeps the writer per-process; Mutex serialises
// concurrent writes from tokio worker threads.
static LOGGER:       OnceLock<Mutex<Logger<LoggerBackend, Formatter3164>>> = OnceLock::new();
static ALSO_STDERR:  AtomicBool = AtomicBool::new(false);
// Severity numeric values match RFC 5424: 0 = EMERG ... 7 = DEBUG.
// We store as u8 so the threshold check is a simple integer compare.
static MIN_SEVERITY: AtomicU8 = AtomicU8::new(Severity::LOG_INFO as u8);

/// Initialise syslog.  Must be called once, before the tokio runtime starts.
///
/// `also_stderr` mirrors every emitted line to stderr (useful in foreground
/// mode where you want both the syslog record and live console output).
///
/// Returns Err if the AF_UNIX socket to syslogd cannot be opened.  On FreeBSD
/// that path is /var/run/log; on Linux it is /dev/log.  Both are created by
/// syslogd at startup, so failure here usually means syslogd is not running.
pub fn init(
    ident:        &str,
    facility:     Facility,
    min_severity: Severity,
    also_stderr:  bool,
) -> anyhow::Result<()> {
    ALSO_STDERR.store(also_stderr, Ordering::Relaxed);
    MIN_SEVERITY.store(min_severity as u8, Ordering::Relaxed);

    let formatter = Formatter3164 {
        facility,
        hostname: None,
        process: ident.to_string(),
        pid: std::process::id(),
    };

    let logger = syslog::unix(formatter)
        .map_err(|e| anyhow::anyhow!("failed to connect to syslog socket: {}", e))?;

    LOGGER.set(Mutex::new(logger))
        .map_err(|_| anyhow::anyhow!("slog::init called more than once"))?;

    Ok(())
}

/// Emit a syslog message if `severity` meets the configured minimum.
///
/// Errors from the underlying socket write are silently dropped: logging the
/// failure-to-log would be circular, and we don't want a transient syslog
/// hiccup to bubble up into the connection-handling path.
pub fn emit(severity: Severity, msg: &str) {
    let min = MIN_SEVERITY.load(Ordering::Relaxed);
    // RFC 5424: smaller numeric severity = more important.
    // Drop messages strictly less important than the configured threshold.
    if (severity as u8) > min {
        return;
    }

    if ALSO_STDERR.load(Ordering::Relaxed) {
        eprintln!("[tarpit/{}] {msg}", severity_label(severity));
    }

    let Some(mtx) = LOGGER.get() else { return };
    let Ok(mut logger) = mtx.lock() else { return };

    let _ = match severity {
        Severity::LOG_EMERG   => logger.emerg(msg),
        Severity::LOG_ALERT   => logger.alert(msg),
        Severity::LOG_CRIT    => logger.crit(msg),
        Severity::LOG_ERR     => logger.err(msg),
        Severity::LOG_WARNING => logger.warning(msg),
        Severity::LOG_NOTICE  => logger.notice(msg),
        Severity::LOG_INFO    => logger.info(msg),
        Severity::LOG_DEBUG   => logger.debug(msg),
    };
}

// --- Convenience wrappers --------------------------------------------------

#[inline] pub fn info(msg: &str)    { emit(Severity::LOG_INFO,    msg); }
#[inline] pub fn notice(msg: &str)  { emit(Severity::LOG_NOTICE,  msg); }
#[inline] pub fn warning(msg: &str) { emit(Severity::LOG_WARNING, msg); }
#[inline] pub fn err(msg: &str)     { emit(Severity::LOG_ERR,     msg); }
#[inline] pub fn debug(msg: &str)   { emit(Severity::LOG_DEBUG,   msg); }

/// Log a completed tarpit session.  Always emitted at INFO since it is the
/// primary product of the daemon.
pub fn log_session(
    service:     &str,
    src_ip:      &str,
    src_port:    u16,
    duration_ms: u128,
    reason:      &str,
) {
    let msg = format!(
        "service={service} src_ip={src_ip} src_port={src_port} \
         duration_ms={duration_ms} reason={reason}"
    );
    emit(Severity::LOG_INFO, &msg);
}

// --- Parsing helpers -------------------------------------------------------

pub fn parse_facility(s: &str) -> anyhow::Result<Facility> {
    Ok(match s.to_lowercase().as_str() {
        "kern"   => Facility::LOG_KERN,
        "user"   => Facility::LOG_USER,
        "mail"   => Facility::LOG_MAIL,
        "daemon" => Facility::LOG_DAEMON,
        "auth"   => Facility::LOG_AUTH,
        "lpr"    => Facility::LOG_LPR,
        "news"   => Facility::LOG_NEWS,
        "uucp"   => Facility::LOG_UUCP,
        "cron"   => Facility::LOG_CRON,
        "local0" => Facility::LOG_LOCAL0,
        "local1" => Facility::LOG_LOCAL1,
        "local2" => Facility::LOG_LOCAL2,
        "local3" => Facility::LOG_LOCAL3,
        "local4" => Facility::LOG_LOCAL4,
        "local5" => Facility::LOG_LOCAL5,
        "local6" => Facility::LOG_LOCAL6,
        "local7" => Facility::LOG_LOCAL7,
        other    => anyhow::bail!(
            "unknown syslog facility '{}'; \
             use daemon, auth, local0..local7, etc.", other),
    })
}

pub fn parse_priority(s: &str) -> anyhow::Result<Severity> {
    Ok(match s.to_lowercase().as_str() {
        "emerg"            => Severity::LOG_EMERG,
        "alert"            => Severity::LOG_ALERT,
        "crit"             => Severity::LOG_CRIT,
        "err" | "error"    => Severity::LOG_ERR,
        "warn" | "warning" => Severity::LOG_WARNING,
        "notice"           => Severity::LOG_NOTICE,
        "info"             => Severity::LOG_INFO,
        "debug"            => Severity::LOG_DEBUG,
        other              => anyhow::bail!(
            "unknown log level '{}'; \
             use debug, info, notice, warn, err", other),
    })
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::LOG_EMERG   => "EMERG",
        Severity::LOG_ALERT   => "ALERT",
        Severity::LOG_CRIT    => "CRIT",
        Severity::LOG_ERR     => "ERR",
        Severity::LOG_WARNING => "WARN",
        Severity::LOG_NOTICE  => "NOTICE",
        Severity::LOG_INFO    => "INFO",
        Severity::LOG_DEBUG   => "DEBUG",
    }
}
