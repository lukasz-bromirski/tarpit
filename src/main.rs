// tarpit - universal multi-protocol network tarpit daemon
//
// Entry-point responsibilities (all single-threaded, before tokio starts):
//   1. Parse CLI arguments
//   2. Load and validate configuration
//   3. Install ring as the default TLS crypto provider (see note below)
//   4. Install a process-wide panic hook that logs panics to syslog
//   5. Optionally daemonize (fork must precede tokio runtime creation)
//   6. Initialise syslog
//   7. Start tokio multi-thread runtime
//   8. Spawn one service-watcher task per configured service
//   9. Wait for SIGTERM/SIGINT then clean up
//
// Crypto provider note:
//   rustls 0.23 requires an explicit default provider when multiple providers
//   are compiled.  We pin tokio-rustls to ring in Cargo.toml, but install the
//   default here as a belt-and-suspenders measure.  tls.rs uses
//   builder_with_provider(ring) directly so it works even without a global
//   default.

mod config;
mod http_drip;
mod ip_profile;
mod service;
mod slog;
mod smtp_drip;
mod stats;
mod tls;

use clap::Parser;
use config::Config;
use stats::TarpitStats;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name    = "tarpit",
    about   = "Universal multi-protocol network tarpit",
    version,
    long_about = "Traps brute-force scanners by accepting connections and responding\n\
                  as slowly as possible, wasting attacker resources.\n\
                  Redirect real-service ports to the high tarpit ports with pf(4) rdr rules."
)]
struct Cli {
    /// Path to TOML configuration file
    #[arg(
        short, long,
        default_value = "/usr/local/etc/tarpit/tarpit.toml",
        value_name    = "FILE"
    )]
    config: std::path::PathBuf,

    /// Stay in the foreground; log to stderr as well as syslog
    #[arg(short, long)]
    foreground: bool,

    /// Validate configuration and exit (no services started)
    #[arg(long)]
    check: bool,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    // --- Load config (single-threaded, before any fork) --------------------
    let config = match Config::load(&cli.config) {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("tarpit: configuration error: {e:#}");
            std::process::exit(1);
        }
    };

    if cli.check {
        println!(
            "tarpit: configuration OK ({} service(s) defined)",
            config.services.len()
        );
        for s in &config.services {
            println!("  {:12} port={:<6} tls={} mode={:?}",
                s.name, s.bind_port, s.tls.is_some(), s.tarpit_mode);
        }
        return;
    }

    // --- Install ring as default TLS crypto provider -----------------------
    // Must happen before any TLS work and before tokio starts (thread-safety).
    // Returns Err if a provider is already installed - we ignore that case.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // --- Daemonize before creating threads / tokio runtime -----------------
    if !cli.foreground {
        if let Err(e) = do_daemonize(&config) {
            eprintln!("tarpit: daemonize failed: {e:#}");
            std::process::exit(1);
        }
    }

    // --- Initialise syslog (after fork so the child gets its own socket) ---
    let facility = slog::parse_facility(&config.syslog.facility).unwrap_or_else(|e| {
        eprintln!("tarpit: {e}");
        std::process::exit(1);
    });
    let min_prio = slog::parse_priority(&config.syslog.level).unwrap_or_else(|e| {
        eprintln!("tarpit: {e}");
        std::process::exit(1);
    });
    slog::init(&config.syslog.ident, facility, min_prio, cli.foreground)
        .unwrap_or_else(|e| {
            // syslogd is usually started by the system long before any
            // service, but if for some reason it isn't, we want a clear
            // failure rather than a silent black-hole of all log output.
            eprintln!("tarpit: syslog init failed: {e:#}");
            eprintln!("tarpit: is syslogd running? (FreeBSD: 'service syslogd status')");
            std::process::exit(1);
        });

    // --- Install panic hook that logs to syslog ----------------------------
    // In daemon mode stderr is /dev/null, so panics in tokio tasks would be
    // completely silent.  This hook forwards all panic messages to syslog
    // so they appear in the log regardless of daemonization.
    std::panic::set_hook(Box::new(|info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("(no message)");
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown location".into());
        // Forward the panic to syslog via the `syslog` crate.
        // The crate serialises writes through a Mutex, so re-entrant calls
        // from signal handlers are NOT safe.  Panics in async code surface
        // here on tokio worker threads (not in signal handlers), so this is
        // fine in practice.
        slog::err(&format!("PANIC at {loc}: {msg}"));
    }));

    slog::info(&format!(
        "tarpit v{} starting: {} service(s), pid={}",
        env!("CARGO_PKG_VERSION"),
        config.services.len(),
        std::process::id(),
    ));

    // --- Start multi-threaded tokio runtime --------------------------------
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("tarpit-worker")
        .build()
        .unwrap_or_else(|e| {
            slog::err(&format!("failed to build tokio runtime: {e}"));
            std::process::exit(1);
        });

    rt.block_on(async_main(config));
    slog::info("shutdown complete");
}

// ---------------------------------------------------------------------------
// Async main
// ---------------------------------------------------------------------------

async fn async_main(config: Config) {
    // --- Shared statistics -------------------------------------------------
    // TarpitStats is Arc-wrapped and shared between every service task and the
    // reporter task.  All updates are atomic; no mutex is needed.
    let stats = TarpitStats::new(
        config.services.iter().map(|s| s.name.clone())
    );

    let mut abort_handles = Vec::with_capacity(config.services.len() + 1);

    // --- Periodic reporter task --------------------------------------------
    let interval_secs = config.stats.interval_secs;
    if interval_secs > 0 {
        let stats_r = stats.clone();
        let reporter = tokio::spawn(async move {
            // Skip the first tick so the report doesn't fire immediately at
            // startup before any connections have been processed.
            let mut ticker = tokio::time::interval(
                std::time::Duration::from_secs(interval_secs)
            );
            ticker.tick().await; // consume the immediate first tick
            loop {
                ticker.tick().await;
                slog::info(&stats_r.format_report());
            }
        });
        abort_handles.push(reporter.abort_handle());
    }

    // --- Service tasks -----------------------------------------------------
    for (svc_idx, svc) in config.services.into_iter().enumerate() {
        let name      = svc.name.clone();
        let stats_svc = stats.clone();

        // Inner task: runs the service, returns Result so errors are explicit.
        let service_task = tokio::spawn(async move {
            service::run_service(svc, svc_idx, stats_svc).await
        });

        // Watcher task: awaits the inner task, logs any error or panic.
        // Using two tasks means the watcher doesn't block the runtime and
        // panics (which produce JoinError::Panicked, not Err) are visible.
        let name_w = name.clone();
        let watcher = tokio::spawn(async move {
            match service_task.await {
                Ok(Ok(())) => {
                    // run_service returns Ok(()) immediately after spawning the
                    // detached accept_loop tasks - this is normal, not a stop.
                    // The loops themselves run until a fatal error or shutdown.
                }
                Ok(Err(e)) => {
                    slog::err(&format!("service '{name_w}' fatal error: {e:#}"));
                }
                Err(e) if e.is_panic() => {
                    slog::err(&format!("service '{name_w}' panicked (see panic log above)"));
                }
                Err(e) => {
                    slog::debug(&format!("service '{name_w}' task cancelled: {e}"));
                }
            }
        });

        abort_handles.push(watcher.abort_handle());
    }

    // Wait for shutdown signal (SIGTERM or Ctrl-C)
    wait_for_signal().await;
    slog::info("received shutdown signal, stopping");

    // Emit a final report before exiting so the log always ends with current totals.
    slog::info(&stats.format_report());

    for h in abort_handles {
        h.abort();
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
}

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = sigterm.recv()          => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Daemonize
// ---------------------------------------------------------------------------

fn do_daemonize(config: &Config) -> anyhow::Result<()> {
    use daemonize::Daemonize;
    Daemonize::new()
        .pid_file(&config.daemon.pid_file)
        .working_directory(&config.daemon.working_dir)
        .umask(0o027)
        .start()
        .map_err(|e| anyhow::anyhow!("daemonize: {e}"))?;
    Ok(())
}
