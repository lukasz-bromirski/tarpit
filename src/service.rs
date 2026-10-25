// service.rs - TCP listener and tarpit logic for a single configured service.
//
// Architecture per service:
//   run_service()              ← spawned as a tokio task by main
//     ├─ builds TLS acceptor and Semaphore (shared across all listeners)
//     └─ spawns accept_loop() per bind address  (detached - runs forever)
//          └─ tokio::spawn handle_connection() per accepted socket
//               └─ optional TLS handshake (with its own timeout)
//                    └─ tarpit_loop<S>() (generic over plain/TLS stream)
//
// Dual-stack: a single ServiceConfig with bind_addrs = ["127.0.0.1", "::1"]
// produces two accept_loop tasks sharing one Semaphore, so max_connections
// is enforced across both address families combined.
//
// accept() error handling (FreeBSD / BSD-specific note):
//   On FreeBSD, accept(2) surfaces ECONNABORTED to userspace when a client
//   establishes and immediately RSTs a connection before accept() returns.
//   Linux handles this internally and never returns ECONNABORTED from accept().
//   RFC 793 and UNPv1 §16.6 both require servers to handle this gracefully
//   by calling accept() again.  We treat it (and a small set of similar
//   transient errors) as non-fatal: log at debug level and retry.
//   Only errors that indicate the socket itself is broken (EBADF, ENOTSOCK,
//   EMFILE, …) cause the accept loop to exit.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;

use crate::config::{ServiceConfig, TarpitMode};
use crate::slog;
use crate::stats::TarpitStats;
use crate::tls;

// ---------------------------------------------------------------------------
// Service entry point
// ---------------------------------------------------------------------------

/// Bind all configured addresses, spawn a detached accept loop per address,
/// then return.  The accept loops run for the lifetime of the process.
pub async fn run_service(cfg: ServiceConfig, svc_idx: usize, stats: Arc<TarpitStats>) -> anyhow::Result<()> {
    // Build TLS acceptor once; shared (via Arc inside TlsAcceptor) across
    // all listeners and all connection handler tasks for this service.
    let tls_acceptor: Option<TlsAcceptor> = match &cfg.tls {
        Some(tls_cfg) => {
            let acc = tls::build_acceptor(tls_cfg)
                .map_err(|e| anyhow::anyhow!("service '{}': TLS init: {}", cfg.name, e))?;
            Some(acc)
        }
        None => None,
    };

    // One semaphore shared across all listeners for this service so that
    // max_connections is a per-service cap, not a per-address cap.
    let semaphore = Arc::new(Semaphore::new(cfg.max_connections));
    let cfg       = Arc::new(cfg);

    for addr_str in &cfg.bind_addrs {
        let bind_ip: std::net::IpAddr = addr_str
            .parse()
            .map_err(|e| anyhow::anyhow!("service '{}': bad bind_addr '{}': {}", cfg.name, addr_str, e))?;
        let addr = SocketAddr::new(bind_ip, cfg.bind_port);

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| anyhow::anyhow!("service '{}': bind {}: {}", cfg.name, addr, e))?;

        slog::info(&format!(
            "service '{}' listening on {} (tls={}, mode={:?}, max_conn={})",
            cfg.name, addr, cfg.tls.is_some(), cfg.tarpit_mode, cfg.max_connections,
        ));

        // Detach: the accept loop is an independent task.  Dropping its
        // JoinHandle here does NOT cancel it (tokio docs: "Dropping a
        // JoinHandle does not abort the task").  Errors are logged from
        // within accept_loop itself so they're visible in syslog.
        tokio::spawn(accept_loop(
            listener,
            cfg.clone(),
            semaphore.clone(),
            tls_acceptor.clone(),
            stats.clone(),
            svc_idx,
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Accept loop (one per bind address, detached)
// ---------------------------------------------------------------------------

async fn accept_loop(
    listener:  TcpListener,
    cfg:       Arc<ServiceConfig>,
    semaphore: Arc<Semaphore>,
    acceptor:  Option<TlsAcceptor>,
    stats:     Arc<TarpitStats>,
    svc_idx:   usize,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,

            Err(e) => {
                // Classify the error: transient (retry) vs fatal (stop).
                //
                // Transient errors on FreeBSD:
                //   ECONNABORTED (ConnectionAborted): client RST'd before
                //     accept() returned.  Extremely common on scanned ports.
                //     BSD surfaces this; Linux does not.  Always retry.
                //   EINTR (Interrupted): signal interrupted the syscall.
                //   EWOULDBLOCK / EAGAIN: spurious wakeup from kqueue.
                //   ENOBUFS / ENOMEM: temporary resource pressure; retry
                //     after a brief pause.
                //
                // Fatal errors: anything else (EBADF, ENOTSOCK, EMFILE,
                //   ENFILE, EACCES, …) indicates the socket is broken and
                //   there's no point retrying.
                use std::io::ErrorKind::*;
                match e.kind() {
                    ConnectionAborted | // ECONNABORTED - most common on BSD
                    ConnectionReset   | // ECONNRESET
                    Interrupted       | // EINTR
                    WouldBlock        => {
                        // Transient - log at debug level and retry immediately.
                        slog::debug(&format!(
                            "service '{}': transient accept error (retrying): {}",
                            cfg.name, e
                        ));
                        continue;
                    }
                    OutOfMemory       | // ENOMEM
                    Other if is_enobufs(&e) => {
                        // Resource pressure - brief pause before retrying.
                        slog::warning(&format!(
                            "service '{}': resource pressure on accept, pausing 1s: {}",
                            cfg.name, e
                        ));
                        sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                    _ => {
                        // Fatal - log at error level and stop this listener.
                        slog::err(&format!(
                            "service '{}': fatal accept error, listener stopping: {}",
                            cfg.name, e
                        ));
                        return;
                    }
                }
            }
        };

        // Non-blocking capacity check.  At cap: RST immediately.
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p)  => p,
            Err(_) => {
                slog::warning(&format!(
                    "service '{}' at capacity ({}), dropping {}",
                    cfg.name, cfg.max_connections, peer.ip()
                ));
                drop(stream); // RST
                continue;
            }
        };

        let cfg      = cfg.clone();
        let acceptor = acceptor.clone();
        let stats    = stats.clone();

        tokio::spawn(async move {
            let _permit = permit; // released when this task ends
            handle_connection(stream, peer, cfg, acceptor, stats, svc_idx).await;
        });
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(
    stream:   TcpStream,
    peer:     SocketAddr,
    cfg:      Arc<ServiceConfig>,
    acceptor: Option<TlsAcceptor>,
    stats:    Arc<TarpitStats>,
    svc_idx:  usize,
) {
    let _ = stream.set_nodelay(true);
    // Enable TCP keepalive so stateful middleboxes (NAT, firewalls) don't
    // silently reap the connection on us during long idle periods between
    // ticks.  Endlessh sets this on the listening socket; we set it per
    // accepted socket which is equivalent on FreeBSD.
    // Failure is non-fatal — the tarpit still works without it, just shorter.
    let _ = set_keepalive(&stream);
    let start = Instant::now();
    let max_t = Duration::from_secs(cfg.connection_timeout_secs);

    // Resolve ssh_adaptive → concrete mode using this peer's recent history.
    // We clone the ServiceConfig because every other code path expects an
    // owned/Arc'd cfg with a concrete tarpit_mode set.  Cost: one shallow
    // Vec/String clone per connection — invisible against connection lifetime.
    let cfg: Arc<ServiceConfig> = if matches!(cfg.tarpit_mode, TarpitMode::SshAdaptive) {
        let resolved = if crate::ip_profile::is_persistent_short_scanner(peer.ip()) {
            TarpitMode::Lines
        } else {
            TarpitMode::SshKex
        };
        let mut new_cfg = (*cfg).clone();
        new_cfg.tarpit_mode = resolved;
        Arc::new(new_cfg)
    } else {
        cfg
    };

    // Record connection start - updates current count and peak.
    stats.on_connect(svc_idx);

    let reason = match timeout(max_t, run_tarpit(stream, &cfg, acceptor)).await {
        Ok(Ok(()))    => "client_disconnected",
        Ok(Err(_))    => "io_error",
        Err(_elapsed) => "timeout",
    };

    let duration_ms = start.elapsed().as_millis();

    // Record connection end - decrements current, accumulates wasted time.
    stats.on_disconnect(svc_idx, duration_ms);

    // Feed the per-IP profile so future adaptive lookups can act on the
    // outcome of this session.  This is a fast in-memory operation.
    crate::ip_profile::record_session(peer.ip(), duration_ms, reason);

    slog::log_session(
        &cfg.name,
        &peer.ip().to_string(),
        peer.port(),
        duration_ms,
        reason,
    );
}

// ---------------------------------------------------------------------------
// TLS dispatch
// ---------------------------------------------------------------------------

async fn run_tarpit(
    stream:   TcpStream,
    cfg:      &ServiceConfig,
    acceptor: Option<TlsAcceptor>,
) -> anyhow::Result<()> {
    if let Some(acc) = acceptor {
        let hs_timeout = cfg.tls.as_ref()
            .map(|t| t.handshake_timeout_secs)
            .unwrap_or(10);

        let tls_stream = timeout(
            Duration::from_secs(hs_timeout),
            acc.accept(stream),
        )
        .await
        .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))?
        .map_err(|e| anyhow::anyhow!("TLS handshake failed: {}", e))?;

        tarpit_loop(tls_stream, cfg).await
    } else {
        tarpit_loop(stream, cfg).await
    }
}

// ---------------------------------------------------------------------------
// Generic tarpit loop
// ---------------------------------------------------------------------------

async fn tarpit_loop<S>(mut stream: S, cfg: &ServiceConfig) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Dispatch protocol-aware modes to their own loops.  The generic drip
    // loop below doesn't fit them: SshKex wants one write then silence,
    // HttpDrip wants a phased response (status → headers → chunked body),
    // SmtpDrip wants full command/response state-machine engagement.
    match cfg.tarpit_mode {
        TarpitMode::SshKex   => return ssh_kex_loop(stream, cfg).await,
        TarpitMode::HttpDrip => return crate::http_drip::http_drip_loop(stream, cfg).await,
        TarpitMode::SmtpDrip => return crate::smtp_drip::smtp_drip_loop(stream, cfg).await,
        _ => {}
    }

    // Drain buffer: read() on TCP copies at most buf.len() bytes from the kernel
    // receive buffer; the rest stays in-kernel and is read next iteration.
    // 4096 handles standard MTU in one syscall and jumbo frames in three.
    // Lives in the heap-allocated Future state, not the OS thread stack.
    let mut drain_buf = [0u8; 4096];
    let mut cursor: usize = 0;

    // Use first_tick_ms for the very first send, tick_ms for all subsequent ones.
    //
    // Why: SSH, SMTP, and IMAP are server-speaks-first protocols.  Scanners
    // connect and wait silently for the server banner.  Most have a short initial
    // timeout (3-15 s).  If we sleep the full tick_ms (e.g. 10 s) before the
    // first send, those scanners fire their timeout and RST us - we hold them for
    // only one tick instead of hours.
    //
    // Sending one garbage chunk within first_tick_ms (default 500 ms) convinces
    // the scanner that the server is alive and responding.  It then waits
    // patiently for the banner to complete - which it never does - while we
    // continue dripping data at tick_ms intervals.
    //
    // HTTP/HTTPS scanners send a request immediately after connecting (client-
    // speaks-first), so they are already committed before our first send fires.
    // first_tick_ms is less critical for those but causes no harm.
    let mut first_tick = true;

    loop {
        let tick = if first_tick {
            first_tick = false;
            // Add a small jitter to the initial send too (±25% of first_tick_ms)
            // so scanners cannot fingerprint us purely by the first-byte timing.
            let j = cfg.first_tick_ms / 4;
            jittered_duration(cfg.first_tick_ms, j)
        } else {
            jittered_duration(cfg.tick_ms, cfg.jitter_ms)
        };

        tokio::select! {
            result = stream.read(&mut drain_buf) => {
                match result {
                    Ok(0)  => return Ok(()),        // EOF - clean close
                    Ok(_)  => {}                    // discard; stay in loop
                    Err(e) => return Err(e.into()), // RST etc.
                }
            }

            _ = sleep(tick) => {
                let chunk = make_chunk(cfg, &mut cursor);
                if !chunk.is_empty() {
                    if stream.write_all(&chunk).await.is_err() {
                        return Err(anyhow::anyhow!("write failed"));
                    }
                    if stream.flush().await.is_err() {
                        return Err(anyhow::anyhow!("flush failed"));
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SSH KEX-sit tarpit loop
// ---------------------------------------------------------------------------
//
// Strategy:
//   1. Wait first_tick_ms (with small jitter so we don't ALWAYS hit at the
//      same millisecond from the scanner's perspective).
//   2. Send the configured ssh_banner + \r\n.  Exactly once.
//   3. Stay silent.  Drain whatever the client sends us (their banner, then
//      their KEXINIT, then their KEX_DH_INIT, etc.) and throw it away.
//   4. Hold until the client gives up or our connection_timeout_secs hits.
//
// Why this beats the "lines" mode for SSH:
//   - The "lines" mode times out hard-deadline scanners at ~10 s because
//     the scanner's banner-phase timer is short.
//   - Once we send a real banner, the scanner exits the banner phase and
//     enters the KEX state machine, which has a MUCH longer timeout (30 s
//     to 10 min in libssh2 / Paramiko / OpenSSH client defaults).
//
// Why we don't fake KEXINIT too:
//   - Would require implementing SSH binary packet protocol (32-bit length
//     prefix, padding, MAC field, message type byte, name-list encoding...)
//   - Going past KEXINIT pulls us into Diffie-Hellman which requires real
//     crypto, defeating the "cheap to run" property of a tarpit.
//   - Sitting silent post-banner is enough to extract 30 s - 10 min per
//     scanner; that's already 3 - 60x better than "lines" mode for the
//     hard-timeout cohort.

async fn ssh_kex_loop<S>(mut stream: S, cfg: &ServiceConfig) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Initial delay before sending the banner.  Same logic as the generic
    // loop: small jitter (±25%) so scanners cannot fingerprint us purely
    // by first-byte timing.
    let first_delay = jittered_duration(cfg.first_tick_ms, cfg.first_tick_ms / 4);
    sleep(first_delay).await;

    // Construct the banner with the required CR LF terminator.
    // Capacity hint avoids a re-allocation.
    let mut banner = Vec::with_capacity(cfg.ssh_banner.len() + 2);
    banner.extend_from_slice(cfg.ssh_banner.as_bytes());
    banner.extend_from_slice(b"\r\n");

    stream.write_all(&banner).await?;
    stream.flush().await?;

    // Past this point we never write again.  Just drain reads.
    // The outer `timeout(connection_timeout_secs, ...)` in handle_connection
    // bounds how long we stay here on a silent client.
    let mut drain_buf = [0u8; 4096];
    loop {
        match stream.read(&mut drain_buf).await {
            Ok(0)  => return Ok(()),         // EOF - client closed cleanly
            Ok(_)  => continue,              // discard whatever they sent
            Err(e) => return Err(e.into()),  // RST or similar
        }
    }
}

// ---------------------------------------------------------------------------
// Data generation
// ---------------------------------------------------------------------------

fn make_chunk(cfg: &ServiceConfig, cursor: &mut usize) -> Vec<u8> {
    match cfg.tarpit_mode {
        TarpitMode::Lines  => random_line(cfg.line_min_len, cfg.line_max_len),
        TarpitMode::Static => {
            let data = cfg.static_data.as_bytes();
            if data.is_empty() { return Vec::new(); }
            let n = cfg.bytes_per_tick.min(data.len());
            let mut chunk = Vec::with_capacity(n);
            for _ in 0..n {
                chunk.push(data[*cursor % data.len()]);
                *cursor = cursor.wrapping_add(1);
            }
            chunk
        }
        TarpitMode::Hold => Vec::new(),
        // The protocol-aware modes never reach make_chunk: tarpit_loop
        // dispatches them to their own per-protocol loops first.  These
        // arms exist purely to satisfy the exhaustiveness check.
        // unreachable!() over a wildcard `_` arm so any future TarpitMode
        // variant added without a corresponding dispatch in tarpit_loop
        // still triggers a compile error rather than silently falling
        // through to a wrong behaviour.
        TarpitMode::SshKex => unreachable!(
            "ssh_kex mode must be handled by ssh_kex_loop, not make_chunk"
        ),
        TarpitMode::HttpDrip => unreachable!(
            "http_drip mode must be handled by http_drip_loop, not make_chunk"
        ),
        TarpitMode::SmtpDrip => unreachable!(
            "smtp_drip mode must be handled by smtp_drip_loop, not make_chunk"
        ),
        TarpitMode::SshAdaptive => unreachable!(
            "ssh_adaptive mode must be resolved to a concrete mode in handle_connection \
             before reaching make_chunk"
        ),
    }
}

fn random_line(min_len: usize, max_len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let len = if min_len >= max_len { min_len } else { rng.gen_range(min_len..=max_len) };
    let mut line: Vec<u8> = (0..len).map(|_| rng.gen_range(0x20u8..=0x7Eu8)).collect();

    // CRITICAL: RFC 4253 §4.2 — any line beginning with "SSH-" IS the server's
    // version identification string.  If our random data happens to start with
    // "SSH-", the client believes the banner phase is complete, attempts the
    // real SSH key exchange, and disconnects within milliseconds when nothing
    // valid follows.  Per-line probability is 1/(95^4) ≈ 1-in-81M, but over
    // millions of scanner connections it WILL hit.  Endlessh fixed this same
    // bug in 2017 (commit a9b3e22).
    if line.len() >= 4 && &line[..4] == b"SSH-" {
        line[0] = b'X';
    }

    line.push(b'\r');
    line.push(b'\n');
    line
}

fn jittered_duration(base_ms: u64, jitter_ms: u64) -> Duration {
    if jitter_ms == 0 { return Duration::from_millis(base_ms); }
    let jitter = rand::thread_rng().gen_range(0..=jitter_ms);
    Duration::from_millis(base_ms.saturating_add(jitter))
}

/// Check if an IO error is ENOBUFS (no libc constant in std::io::ErrorKind).
fn is_enobufs(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOBUFS)
}

/// Enable TCP keepalive on a tokio TcpStream via libc setsockopt(SO_KEEPALIVE).
///
/// Why not use socket2: we already depend on libc and adding socket2 just for
/// one setsockopt isn't worth the extra dependency surface.
///
/// FreeBSD inherits keepalive timing from system sysctls
/// (net.inet.tcp.keepidle / keepintvl / keepcnt — defaults 2hr/75s/8).
/// That's intentionally LONG: we don't want keepalive probes to be
/// frequent enough to wake up scanners, just frequent enough to keep NAT
/// state alive on the path.  System defaults are fine for both goals.
fn set_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let enable: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        )
    };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}
