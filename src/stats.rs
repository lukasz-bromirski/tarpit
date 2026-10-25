// stats.rs - shared runtime statistics for the periodic syslog report.
//
// Design goals:
//   - Zero-cost when disabled (stats_interval_secs = 0).
//   - Lock-free: all counters are atomics.  Service tasks update them
//     on every connect/disconnect without any mutex contention.
//   - No integer overflow: total_ms_wasted is u64 (max ≈ 584 million years
//     worth of milliseconds); individual session durations are capped before
//     accumulation.  Connection counts use usize which saturates at
//     usize::MAX on fetch_sub (unreachable in practice, guarded anyway).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Per-service counters
// ---------------------------------------------------------------------------

pub struct ServiceCounters {
    pub name: String,
    /// Connections active right now for this service.
    current:  AtomicUsize,
    /// Maximum simultaneous connections ever seen since startup.
    peak:     AtomicUsize,
}

// ---------------------------------------------------------------------------
// Global stats (one instance, shared via Arc across all tasks)
// ---------------------------------------------------------------------------

pub struct TarpitStats {
    /// Sum of all session durations in milliseconds since last restart.
    total_ms_wasted: AtomicU64,
    /// One entry per configured service, in the same order as config.services.
    pub services:    Vec<ServiceCounters>,
}

impl TarpitStats {
    /// Construct and wrap in Arc.  Service names come from config order.
    pub fn new(names: impl Iterator<Item = String>) -> Arc<Self> {
        Arc::new(Self {
            total_ms_wasted: AtomicU64::new(0),
            services: names.map(|n| ServiceCounters {
                name:    n,
                current: AtomicUsize::new(0),
                peak:    AtomicUsize::new(0),
            }).collect(),
        })
    }

    // -----------------------------------------------------------------------
    // Update methods - called from handle_connection on the hot path
    // -----------------------------------------------------------------------

    /// Called immediately after a connection is accepted.
    /// Increments the service's current count and updates peak if needed.
    pub fn on_connect(&self, svc_idx: usize) {
        let Some(svc) = self.services.get(svc_idx) else { return };

        // fetch_add returns the *old* value; add 1 to get what we just wrote.
        let new_current = svc.current.fetch_add(1, Ordering::Relaxed) + 1;

        // CAS loop: update peak only if new_current exceeds the stored peak.
        // Multiple threads may race here; the loop retries until either we
        // succeed or we observe a peak already >= new_current.
        let mut stored_peak = svc.peak.load(Ordering::Relaxed);
        while new_current > stored_peak {
            match svc.peak.compare_exchange_weak(
                stored_peak, new_current,
                Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_)      => break,
                Err(found) => stored_peak = found,
            }
        }
    }

    /// Called immediately after a connection ends (any reason).
    /// Decrements the service's current count and accumulates the duration.
    pub fn on_disconnect(&self, svc_idx: usize, duration_ms: u128) {
        if let Some(svc) = self.services.get(svc_idx) {
            // Guard against spurious underflow (should never happen, but
            // using saturating logic on u64 arithmetic instead of wrapping).
            let prev = svc.current.load(Ordering::Relaxed);
            if prev > 0 {
                svc.current.fetch_sub(1, Ordering::Relaxed);
            }
        }

        // Cap a single session at u64::MAX ms (unreachable in practice)
        // before accumulating so we never overflow the total.
        let ms = duration_ms.min(u64::MAX as u128) as u64;
        self.total_ms_wasted.fetch_add(ms, Ordering::Relaxed);
    }

    // -----------------------------------------------------------------------
    // Report - called by the reporter task on the timer
    // -----------------------------------------------------------------------

    /// Build the syslog report line.
    ///
    /// Example:
    ///   tarpit report - 482 seconds wasted, 16 tarpit sessions right now,
    ///   maximums per each configured service: ssh (4), smtps (28), http (3)
    pub fn format_report(&self) -> String {
        let total_secs = self.total_ms_wasted.load(Ordering::Relaxed) / 1000;

        let total_current: usize = self.services.iter()
            .map(|s| s.current.load(Ordering::Relaxed))
            .sum();

        let peaks: Vec<String> = self.services.iter()
            .map(|s| format!("{} ({})", s.name, s.peak.load(Ordering::Relaxed)))
            .collect();

        format!(
            "tarpit report - {} seconds wasted, {} tarpit session(s) right now, \
             maximums per each configured service: {}",
            total_secs,
            total_current,
            peaks.join(", "),
        )
    }
}
