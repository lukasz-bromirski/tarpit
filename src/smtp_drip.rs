// smtp_drip.rs — protocol-aware SMTP/SMTPS tarpit (teergrube).
//
// Strategy
// --------
// Engage with the SMTP command state machine like a real but very slow MTA:
//
//   1. Drip the 220 banner byte-by-byte.
//   2. Loop:
//      a. Read one command (until CRLF).
//      b. Sleep tick_ms (the "teergrube" delay).
//      c. Drip the response byte-by-byte.
//      d. EHLO triggers a long multi-line capability list (more bytes to
//         drip = more time on connection).
//   3. When the client says DATA:
//      a. Send 354 slowly.
//      b. Read message body until "\r\n.\r\n" (or timeout) — discarding it.
//         We never deliver, never relay.  This is intentional and ethical:
//         we're not a working MTA, we're a black hole shaped like one.
//      c. Long delay.
//      d. Return "421 try again later" - forcing the sender to re-queue
//         and retry days later, walking back into the same tarpit.
//
// This holds spam-cannon scanners for the full SMTP transaction window
// (typically 60 - 300 s on the first hit) instead of the few hundred ms
// they'd spend on an immediate 5xx reject.
//
// Why 421, not 5xx
// ----------------
// 5xx (permanent failure) tells the sender "give up, this address is dead".
// They mark it bad and stop retrying.  Bad for us - we want them to come
// back.
//
// 421 / 4xx (temporary failure) tells them "I'm busy now, try again".
// They keep the message queued and re-attempt for several days (typical
// MTA default is 4-5 days).  Every retry is another full slow SMTP
// transaction through our tarpit.  Maximum resource extraction.
//
// Why this is open-relay safe
// ---------------------------
// We never reach a successful "250 OK" after DATA - we always return 4xx.
// Nothing flows through.  We have no SMTP submission path that could be
// abused to deliver mail anywhere.

use std::time::Duration;

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{sleep, timeout};

use crate::config::ServiceConfig;

// Hard limits to protect us from a malicious client trying to make US the
// resource-exhausted party.
const MAX_COMMAND_LEN:    usize = 4096;       // RFC 5321 §4.5.3.1.4 says 512; we're generous
const MAX_DATA_BYTES:     usize = 10_485_760; // 10 MB cap per message - we drain and discard
const READ_TIMEOUT_SECS:  u64   = 600;        // 10 min idle read = give up

// ---------------------------------------------------------------------------

#[derive(Default)]
struct SmtpState {
    in_data:    bool,
    helo_seen:  bool,
    mail_seen:  bool,
    rcpt_count: usize,
    error_count:usize,
}

pub async fn smtp_drip_loop<S>(mut stream: S, cfg: &ServiceConfig) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let tick = Duration::from_millis(cfg.tick_ms.max(1));
    let bpt  = cfg.bytes_per_tick.max(1);
    // StdRng (not thread_rng) because we hold this RNG across .await points;
    // ThreadRng's Rc<UnsafeCell<...>> is !Send and tokio::spawn requires Send.
    let mut rng = StdRng::from_entropy();

    // -- 1. Greeting.  Brief jittered pause first to look natural.
    sleep(jittered(cfg.first_tick_ms, cfg.first_tick_ms / 4, &mut rng)).await;

    // Multi-line 220 banner (RFC 5321 §4.2 — continuation lines use "220-",
    // the FINAL line uses "220 ").  Each line is dripped byte-by-byte and
    // followed by a short pause — same technique OpenBSD spamd uses to
    // burn 3-5 minutes of session time before the client can even send
    // EHLO.  The client MUST read every line of a multi-line response
    // before issuing the next command; that's what makes this effective.
    let banner = generate_banner_lines(&cfg.hostname, cfg.smtp_banner_lines, &mut rng);
    let last_idx = banner.len() - 1;
    for (i, line_text) in banner.iter().enumerate() {
        let prefix = if i == last_idx { "220 " } else { "220-" };
        let line = format!("{}{}\r\n", prefix, line_text);
        write_slow(&mut stream, line.as_bytes(), bpt, tick).await?;
        // Small pause between continuation lines so byte-drip + line-drip
        // compound, not just byte-drip alone.  Skip after the final line.
        if i < last_idx {
            sleep(tick).await;
        }
    }

    // -- 2. Command loop.
    let mut state = SmtpState::default();
    let mut read_buf = [0u8; 1024];
    let mut accum: Vec<u8> = Vec::with_capacity(MAX_COMMAND_LEN);
    let mut data_bytes_seen: usize = 0;

    loop {
        // Read until we have a full terminator.
        // In DATA mode the terminator is the dot-line "\r\n.\r\n".
        // Otherwise it's a regular CRLF.
        let terminator: &[u8] = if state.in_data { b"\r\n.\r\n" } else { b"\r\n" };

        let term_pos = loop {
            if let Some(p) = find_subseq(&accum, terminator) {
                break p;
            }
            // Read more.  Bounded by READ_TIMEOUT_SECS so a silent
            // client doesn't hold us forever after sending half a command.
            let n = match timeout(
                Duration::from_secs(READ_TIMEOUT_SECS),
                stream.read(&mut read_buf),
            ).await {
                Err(_)          => return Ok(()),         // idle timeout
                Ok(Ok(0))       => return Ok(()),         // clean EOF
                Ok(Ok(n))       => n,
                Ok(Err(e))      => return Err(e.into()),  // RST etc.
            };
            accum.extend_from_slice(&read_buf[..n]);

            // Resource protection: cap how much we'll buffer.
            if state.in_data {
                data_bytes_seen += n;
                if data_bytes_seen > MAX_DATA_BYTES {
                    // Buffer cap hit.  We could continue here, but a client
                    // pumping past 10 MB into our discard buffer is already
                    // pathological.  Bail with a 421 so they re-queue and
                    // try again later (smaller batch, ideally).
                    //
                    // No need to reset data_bytes_seen / state.in_data —
                    // we return immediately after sending the response.
                    accum.clear();
                    sleep(tick).await;
                    write_slow(&mut stream,
                        b"421 4.3.4 Mail system full, try again later\r\n",
                        bpt, tick).await?;
                    return Ok(());
                }
            } else if accum.len() > MAX_COMMAND_LEN {
                accum.clear();
                sleep(tick).await;
                write_slow(&mut stream,
                    b"500 5.5.2 Line too long\r\n",
                    bpt, tick).await?;
                state.error_count += 1;
                continue;
            }
        };

        if state.in_data {
            // We have the entire DATA body sitting in `accum` (we don't
            // actually need to keep it).  Reset and respond.
            accum.clear();
            data_bytes_seen = 0;
            state.in_data = false;
            state.mail_seen = false;
            state.rcpt_count = 0;

            // Long final hold then defer.  We've already burned the client's
            // SMTP transaction time on the multi-step conversation; this
            // adds a final dramatic pause and the all-important 421 so they
            // re-queue.
            sleep(Duration::from_secs(rng_range(&mut rng, 30, 90))).await;
            write_slow(&mut stream,
                b"421 4.7.0 Service temporarily unavailable, please try again later\r\n",
                bpt, tick).await?;
            continue;
        }

        // Regular command path.  Pull out the first complete line.
        let line_bytes = accum[..term_pos].to_vec();
        accum.drain(..term_pos + terminator.len());

        let line = String::from_utf8_lossy(&line_bytes).to_string();
        let response = handle_command(&line, &cfg.hostname, &mut state, &mut rng);

        // Teergrube delay before responding.  Random within [tick, 3*tick]
        // so we don't have a perfectly fingerprintable response cadence.
        let extra = rng_range(&mut rng, cfg.tick_ms, cfg.tick_ms * 3);
        sleep(Duration::from_millis(extra)).await;

        write_slow(&mut stream, response.as_bytes(), bpt, tick).await?;

        // After QUIT we politely close.  After too many errors we also bail
        // (some scanners loop on errors forever - protect ourselves).
        let upper = line.trim().to_uppercase();
        if upper.starts_with("QUIT") {
            return Ok(());
        }
        if state.error_count > 20 {
            // Defer with a final 421 and close.
            sleep(tick).await;
            let _ = write_slow(&mut stream,
                b"421 4.7.0 Too many errors, goodbye\r\n",
                bpt, tick).await;
            return Ok(());
        }
    }
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

fn handle_command(
    line:     &str,
    hostname: &str,
    state:    &mut SmtpState,
    rng:      &mut impl Rng,
) -> String {
    let trimmed = line.trim();
    let upper   = trimmed.to_uppercase();
    let verb    = upper.split_whitespace().next().unwrap_or("");

    match verb {
        "HELO" => {
            state.helo_seen = true;
            format!("250 {hostname}\r\n")
        }
        "EHLO" => {
            // Long multi-line response = more bytes to drip = more session time.
            // All capabilities are real Postfix advertises; nothing exotic that
            // would tip off a fingerprinter.
            state.helo_seen = true;
            format!(
                "250-{hostname}\r\n\
                 250-PIPELINING\r\n\
                 250-SIZE 10485760\r\n\
                 250-VRFY\r\n\
                 250-ETRN\r\n\
                 250-STARTTLS\r\n\
                 250-ENHANCEDSTATUSCODES\r\n\
                 250-8BITMIME\r\n\
                 250-DSN\r\n\
                 250-SMTPUTF8\r\n\
                 250 CHUNKING\r\n"
            )
        }
        "STARTTLS" => {
            // Refusing STARTTLS prevents TLS-upgrade attacks against this
            // listener.  If you want a TLS-wrapped tarpit, use the SMTPS
            // service on port 465 with [tls] configured.
            "454 4.7.0 TLS not available due to temporary reason\r\n".to_string()
        }
        "MAIL" => {
            if !state.helo_seen {
                state.error_count += 1;
                "503 5.5.1 Error: send HELO/EHLO first\r\n".to_string()
            } else {
                state.mail_seen  = true;
                state.rcpt_count = 0;
                "250 2.1.0 Ok\r\n".to_string()
            }
        }
        "RCPT" => {
            if !state.mail_seen {
                state.error_count += 1;
                "503 5.5.1 Error: need MAIL command\r\n".to_string()
            } else if state.rcpt_count >= 50 {
                // Postfix default is 1000 but we cap lower - no point letting
                // them announce thousands of recipients to us.
                "452 4.5.3 Too many recipients\r\n".to_string()
            } else {
                state.rcpt_count += 1;
                "250 2.1.5 Ok\r\n".to_string()
            }
        }
        "DATA" => {
            if !state.mail_seen || state.rcpt_count == 0 {
                state.error_count += 1;
                "503 5.5.1 Error: need RCPT command\r\n".to_string()
            } else {
                state.in_data = true;
                "354 End data with <CR><LF>.<CR><LF>\r\n".to_string()
            }
        }
        "RSET" => {
            state.mail_seen  = false;
            state.rcpt_count = 0;
            "250 2.0.0 Ok\r\n".to_string()
        }
        "NOOP" => "250 2.0.0 Ok\r\n".to_string(),
        "VRFY" => {
            // Postfix-style: refuse to confirm/deny addresses (RFC 5321 §7.3).
            "252 2.5.2 Cannot VRFY user, but will accept and attempt delivery\r\n".to_string()
        }
        "HELP" => {
            format!(
                "214-2.0.0 This is Postfix on {hostname}\r\n\
                 214-2.0.0 Commands: HELO EHLO MAIL RCPT DATA RSET NOOP QUIT HELP VRFY ETRN STARTTLS\r\n\
                 214 2.0.0 For more info send mail to postmaster\r\n"
            )
        }
        "QUIT" => format!("221 2.0.0 {hostname} closing connection\r\n"),
        "" => {
            state.error_count += 1;
            "500 5.5.2 Error: bad syntax\r\n".to_string()
        }
        _ => {
            state.error_count += 1;
            // Slight randomisation between "command not recognized" and
            // "syntax error" so logs from many sessions don't look identical.
            if rng.gen_bool(0.5) {
                "502 5.5.2 Error: command not recognized\r\n".to_string()
            } else {
                "500 5.5.2 Error: bad command sequence\r\n".to_string()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn write_slow<W>(
    w: &mut W,
    data: &[u8],
    bytes_per_chunk: usize,
    tick: Duration,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut first = true;
    for slice in data.chunks(bytes_per_chunk) {
        if !first { sleep(tick).await; }
        first = false;
        w.write_all(slice).await?;
        w.flush().await?;
    }
    Ok(())
}

/// Locate `needle` in `haystack`.  std doesn't expose subseq search on
/// byte slices in stable Rust 1.75; this open-codes it.
fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() { return None; }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn jittered(base_ms: u64, jitter_ms: u64, rng: &mut impl Rng) -> Duration {
    if jitter_ms == 0 { return Duration::from_millis(base_ms); }
    Duration::from_millis(base_ms.saturating_add(rng.gen_range(0..=jitter_ms)))
}

fn rng_range(rng: &mut impl Rng, lo: u64, hi: u64) -> u64 {
    if lo >= hi { return lo; }
    rng.gen_range(lo..=hi)
}

// ---------------------------------------------------------------------------
// Multi-line banner generator (spamd-style)
// ---------------------------------------------------------------------------

/// Pool of plausible "service info" lines that real MTAs sometimes emit as
/// part of a multi-line 220 greeting.  Chosen to look like legitimate
/// service notices a security-conscious mail admin would publish — not
/// gibberish, since some scanner heuristics flag obvious nonsense banners.
/// Mixing these across sessions gives the per-host banner fingerprint
/// enough variety that a "did I see this tarpit before" classifier can't
/// match on banner content alone.
const BANNER_CONTINUATIONS: &[&str] = &[
    "this server is monitored for abuse",
    "unauthorized use is prohibited",
    "by connecting you accept the acceptable use policy",
    "excessive connection attempts will be throttled",
    "mail relay restricted to authorized senders",
    "TLS strongly recommended via STARTTLS",
    "reverse DNS verification active",
    "DKIM and SPF policies enforced",
    "greylisting may apply to first-time senders",
    "rate limiting is in effect",
    "please refer to postmaster for service issues",
    "ESMTP service ready, please send HELO/EHLO",
    "this MTA logs connection metadata for audit",
    "abuse reports: postmaster at this domain",
    "no UCE no UBE — see RFC 2505",
    "spam-trap addresses are monitored",
    "automated submissions must use port 587",
    "anonymous relay disabled",
    "service powered by Postfix",
    "connection accepted, awaiting your HELO",
];

/// Build a multi-line 220 greeting consisting of `count` lines.
///
/// Layout:
///   line 0          : "<hostname> ESMTP Postfix (FreeBSD) ready"   (real-looking)
///   lines 1..n-1    : random picks from BANNER_CONTINUATIONS
///   line n-1 (last) : "ESMTP ready, please proceed"                (closer)
///
/// `count` is clamped to [1, 20].  The caller decides the continuation
/// prefix ("220-" vs "220 ") based on whether each line is final.
fn generate_banner_lines(
    hostname: &str,
    count:    usize,
    rng:      &mut impl Rng,
) -> Vec<String> {
    let n = count.clamp(1, 20);
    let mut out = Vec::with_capacity(n);

    // First line — always present, recognisable as a real Postfix-style banner.
    out.push(format!("{hostname} ESMTP Postfix (FreeBSD) ready"));

    if n == 1 {
        return out;
    }

    // Middle lines — random unique picks from the corpus.  We shuffle
    // indices into a tiny scratch buffer rather than allocating a Vec of
    // (count) refs.
    let pool_len = BANNER_CONTINUATIONS.len();
    let mut seen: u64 = 0;   // bitmask, OK because pool_len < 64
    let middle = n.saturating_sub(2);
    for _ in 0..middle {
        // Try up to 8 picks to find an unused entry; fall through to
        // allowing a repeat if we somehow can't (corpus too small).
        let mut idx = 0;
        for _ in 0..8 {
            idx = rng.gen_range(0..pool_len);
            if (seen >> idx) & 1 == 0 {
                seen |= 1u64 << idx;
                break;
            }
        }
        out.push(BANNER_CONTINUATIONS[idx].to_string());
    }

    // Last line — short closer.  Stays in the 220-/220 multi-line frame.
    out.push("ESMTP ready, please proceed".to_string());

    out
}
