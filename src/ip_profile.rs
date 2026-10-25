// ip_profile.rs — per-source-IP recent-session cache, used by the
// `ssh_adaptive` tarpit mode to decide whether to serve a given source
// with ssh_kex (default) or lines (fallback).
//
// Storage model
// -------------
// Global HashMap<IpAddr, Profile> behind a Mutex.  Each profile keeps a
// small ring buffer of the most recent N session outcomes from that IP.
// We touch the cache exactly twice per connection (one lookup at start,
// one record at end), so the mutex is uncontended in practice — locking
// cost is negligible against the connection lifetime.
//
// Memory bound
// ------------
// At peak: ~10k unique scanner IPs * 8 sessions * ~32 bytes ≈ 2.5 MB.
// Stale entries (no activity for PROFILE_TTL) get evicted lazily on
// record_session().  No background thread needed.
//
// What counts as "short io_error"
// -------------------------------
// A session is "short io_error" if its reason was `io_error` AND its
// duration falls in [SHORT_LO_MS, SHORT_HI_MS] — the empirically observed
// window for hard-timeout scanner cohorts.  Pure timeouts (we hit our
// connection_timeout_secs) and clean disconnects don't count.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

// Tuning knobs — kept private; if any of these need to be user-configurable
// we can promote them to the config schema in a later pass.
const MAX_SESSIONS_PER_IP: usize    = 8;
const PROFILE_TTL:         Duration = Duration::from_secs(86_400);  // 24h
const CLEANUP_INTERVAL:    Duration = Duration::from_secs(3_600);   // hourly
const SHORT_LO_MS:         u64      = 8_000;
const SHORT_HI_MS:         u64      = 13_000;
const PERSIST_THRESHOLD:   usize    = 3;

#[derive(Clone, Copy)]
struct SessionRecord {
    duration_ms: u64,
    short_io:    bool,
    #[allow(dead_code)]  // kept for future debug / introspection commands
    at:          Instant,
}

struct Profile {
    recent:    Vec<SessionRecord>,
    last_seen: Instant,
}

static CACHE:        OnceLock<Mutex<HashMap<IpAddr, Profile>>> = OnceLock::new();
static LAST_CLEANUP: OnceLock<Mutex<Instant>>                  = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<IpAddr, Profile>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn last_cleanup() -> &'static Mutex<Instant> {
    LAST_CLEANUP.get_or_init(|| Mutex::new(Instant::now()))
}

/// Record a completed session.  Called from handle_connection once the
/// outcome is known.  `reason` is the same string fed to slog::log_session
/// ("io_error" | "client_disconnected" | "timeout").
pub fn record_session(ip: IpAddr, duration_ms: u128, reason: &str) {
    // Truncate u128→u64: durations are well under u64 capacity (years).
    let duration_ms = duration_ms.min(u64::MAX as u128) as u64;
    let short_io = reason == "io_error"
        && duration_ms >= SHORT_LO_MS
        && duration_ms <= SHORT_HI_MS;

    let now = Instant::now();
    let mut c = cache().lock().expect("ip_profile cache poisoned");

    let p = c.entry(ip).or_insert_with(|| Profile {
        recent:    Vec::with_capacity(MAX_SESSIONS_PER_IP),
        last_seen: now,
    });

    p.recent.push(SessionRecord { duration_ms, short_io, at: now });
    if p.recent.len() > MAX_SESSIONS_PER_IP {
        // Drop the oldest record(s) so the ring stays bounded.  drain() on
        // a Vec is O(N) but N=8 here; not worth a fancier data structure.
        let drop_count = p.recent.len() - MAX_SESSIONS_PER_IP;
        p.recent.drain(..drop_count);
    }
    p.last_seen = now;

    // Opportunistic eviction: piggy-back on whichever record_session
    // happens to cross the cleanup interval.  Avoids a dedicated GC thread.
    let mut last = last_cleanup().lock().expect("ip_profile cleanup poisoned");
    if last.elapsed() > CLEANUP_INTERVAL {
        let cutoff = now.checked_sub(PROFILE_TTL).unwrap_or(now);
        c.retain(|_, p| p.last_seen > cutoff);
        *last = now;
    }
}

/// True iff the IP has racked up PERSIST_THRESHOLD or more "short io_error"
/// sessions in its recent history.  Used by ssh_adaptive to switch this
/// source from ssh_kex to lines on subsequent connections.
pub fn is_persistent_short_scanner(ip: IpAddr) -> bool {
    let c = cache().lock().expect("ip_profile cache poisoned");
    let Some(p) = c.get(&ip) else { return false; };
    let short_count = p.recent.iter().filter(|s| s.short_io).count();
    short_count >= PERSIST_THRESHOLD
}

/// Snapshot of an IP's recent stats - exposed for diagnostics / future
/// command-line query.  Returns None if the IP isn't cached.
#[allow(dead_code)]
pub fn snapshot(ip: IpAddr) -> Option<(usize, usize, u64)> {
    let c = cache().lock().expect("ip_profile cache poisoned");
    let p = c.get(&ip)?;
    let total       = p.recent.len();
    let short_count = p.recent.iter().filter(|s| s.short_io).count();
    let avg_ms      = if total == 0 { 0 } else {
        (p.recent.iter().map(|s| s.duration_ms as u128).sum::<u128>() / total as u128) as u64
    };
    Some((total, short_count, avg_ms))
}
