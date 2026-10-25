// http_drip.rs — protocol-aware HTTP/HTTPS tarpit.
//
// Strategy
// --------
//   1. Read the client's request line + headers (with a short read timeout
//      so a silent client doesn't deadlock us).
//   2. Sleep first_tick_ms (small jitter), so it looks like normal server
//      processing rather than instant-response.
//   3. Drip a plausible "HTTP/1.1 200 OK" status line byte-by-byte.
//   4. Drip plausible response headers (Server, Date, Cache-Control,
//      Set-Cookie, Transfer-Encoding: chunked, ...).  Headers are
//      randomised per session for variety.
//   5. Open the chunked-encoded body with <!DOCTYPE>...<html><head>.
//   6. Stream a randomised <head> section: <meta>, <link>, <script>...
//   7. Send </head><body> and then stream <body> content forever:
//      <h2>, <p>, <ul>, <div>, etc.  Plausible structure, random words
//      drawn from a pool.
//   8. NEVER send the terminating "0\r\n\r\n" chunk - the client thinks
//      "more body is still coming" and waits until its own timeout fires
//      or our connection_timeout_secs expires.
//
// Why chunked encoding (not Content-Length)
// -----------------------------------------
// With chunked we don't have to lie about a length up front.  If we set
// Content-Length: 9999999999 and never deliver, many clients give up at
// the first mismatch.  Chunked is open-ended by design; we just keep
// shovelling chunks.
//
// Why template-based generation, not Markov chains
// ------------------------------------------------
// Scanners aren't reading the HTML content - they're matching status
// codes, header fields, and structural tokens (<form>, <input>, common
// admin paths).  A template-based generator with random word selection
// gives plenty of variety for that use case without the corpus and
// table-size cost of a Markov chain.  If a real Markov generator is
// ever needed, this module is the place to drop it in.

use std::time::Duration;

use rand::{Rng, seq::SliceRandom, SeedableRng};
use rand::rngs::StdRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{sleep, timeout};

use crate::config::ServiceConfig;

// ---------------------------------------------------------------------------
// Vocabulary - kept small so we don't bloat the binary; large enough for
// recognisable variety across thousands of sessions.
// ---------------------------------------------------------------------------

const WORDS: &[&str] = &[
    "lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing",
    "elit", "sed", "eiusmod", "tempor", "incididunt", "labore", "magna",
    "aliqua", "enim", "minim", "veniam", "quis", "nostrud", "exercitation",
    "ullamco", "laboris", "nisi", "aliquip", "commodo", "consequat", "duis",
    "aute", "irure", "reprehenderit", "voluptate", "velit", "esse", "cillum",
    "fugiat", "nulla", "pariatur", "excepteur", "sint", "occaecat", "cupidatat",
    "proident", "sunt", "culpa", "officia", "deserunt", "mollit", "anim",
    "laborum", "system", "service", "platform", "solution", "enterprise",
    "framework", "module", "component", "interface", "process", "request",
    "response", "session", "configuration", "deployment", "environment",
];

const CSS_CLASSES: &[&str] = &[
    "container", "row", "col-md-6", "col-lg-4", "wrapper", "content",
    "sidebar", "header", "footer", "nav", "menu", "section", "article",
    "card", "panel", "btn", "btn-primary", "form-group", "alert",
];

const URL_PATHS: &[&str] = &[
    "/about", "/contact", "/products", "/services", "/blog", "/news",
    "/login", "/register", "/dashboard", "/account", "/cart", "/checkout",
    "/api/v1/users", "/api/v2/data", "/wp-admin", "/admin/login",
];

const JS_LIBS: &[&str] = &[
    "jquery.min.js", "bootstrap.bundle.min.js", "vue.global.min.js",
    "react.production.min.js", "lodash.min.js", "moment.min.js",
    "axios.min.js", "chart.min.js", "d3.min.js", "popper.min.js",
];

const CSS_LIBS: &[&str] = &[
    "bootstrap.min.css", "style.css", "main.css", "theme.css",
    "fontawesome.min.css", "animate.min.css", "normalize.css",
];

const WP_THEMES: &[&str] = &[
    "twentytwentyfour", "twentytwentythree", "astra", "divi", "oceanwp",
    "generatepress", "hello-elementor", "kadence", "neve",
];

const WP_PLUGINS: &[&str] = &[
    "woocommerce", "yoast-seo", "contact-form-7", "elementor",
    "wordfence", "all-in-one-seo-pack", "akismet", "jetpack",
];

// ---------------------------------------------------------------------------
// Public entry point - invoked by service::tarpit_loop when tarpit_mode
// is HttpDrip.
// ---------------------------------------------------------------------------

pub async fn http_drip_loop<S>(mut stream: S, cfg: &ServiceConfig) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let tick = Duration::from_millis(cfg.tick_ms.max(1));
    let bpt  = cfg.bytes_per_tick.max(1);
    // StdRng (not thread_rng) because we hold this RNG across .await points.
    // ThreadRng contains Rc<UnsafeCell<...>> which is !Send, so a future that
    // keeps a ThreadRng alive across an await cannot be passed to tokio::spawn.
    // StdRng is Send + Sync and seeds from the OS entropy pool.
    let mut rng = StdRng::from_entropy();

    // -- 1. Read the request (up to 8 KiB or 10 s, whichever first).
    // We don't actually parse the request - we just need to drain it so the
    // client's kernel send buffer doesn't back-pressure and stall them.
    let mut req_buf = [0u8; 8192];
    let _ = timeout(Duration::from_secs(10), async {
        loop {
            match stream.read(&mut req_buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    // Stop when we see end-of-headers (CRLF CRLF) or the
                    // buffer fills.  Either way we have enough to respond.
                    if req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        return;
                    }
                }
            }
        }
    }).await;

    // -- 2. Brief processing pause before we start writing.
    let jitter = cfg.first_tick_ms / 4;
    sleep(jittered(cfg.first_tick_ms, jitter, &mut rng)).await;

    // -- 3. Status line, dripped.
    write_slow(&mut stream, b"HTTP/1.1 200 OK\r\n", bpt, tick).await?;

    // -- 4. Headers, each line dripped, with `tick` between lines.
    let headers = build_headers(&cfg.hostname, &mut rng);
    for line in headers {
        write_slow(&mut stream, line.as_bytes(), bpt, tick).await?;
        write_slow(&mut stream, b"\r\n", bpt, tick).await?;
    }
    write_slow(&mut stream, b"\r\n", bpt, tick).await?;  // end-of-headers

    // -- 5. Open the chunked body.  Each chunk from now on is sent atomically
    //       (the chunked framing is fragile under arbitrary splitting), but
    //       we sleep `tick` between chunks.
    write_chunk(&mut stream, b"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n").await?;
    sleep(tick).await;

    // -- 6. Random <head> section: 8 - 20 elements.
    let n_head: usize = rng.gen_range(8..=20);
    for _ in 0..n_head {
        let element = generate_head_element(&cfg.hostname, &mut rng);
        let line = format!("    {element}\n");
        write_chunk(&mut stream, line.as_bytes()).await?;
        sleep(tick).await;
    }

    // -- 7. Body open.
    write_chunk(&mut stream, b"</head>\n<body>\n").await?;
    sleep(tick).await;

    // -- 8. Infinite body stream.  Returns Err(EPIPE/ECONNRESET) when the
    //       client gives up, which propagates up to handle_connection and
    //       gets logged as the session reason.
    loop {
        let element = generate_body_element(&mut rng);
        write_chunk(&mut stream, element.as_bytes()).await?;
        sleep(tick).await;
    }
}

// ---------------------------------------------------------------------------
// Write helpers
// ---------------------------------------------------------------------------

/// Write `data` in `bytes_per_chunk` slices with `tick` between slices.
/// Used for parts of the response where byte-level dripping is safe
/// (status line, headers).
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

/// Send one chunked-encoding chunk atomically: "<hex_len>\r\n<data>\r\n".
/// Body framing is too fragile under arbitrary splitting (a parser that
/// has read "1" doesn't know if the next byte is "f\r\n" or "\r\n"), so
/// we send each chunk in one write and let `tick` between chunks do the
/// dripping.
async fn write_chunk<W>(w: &mut W, data: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    // Pre-format the whole frame into one Vec so a single write_all call
    // delivers everything atomically (well, at the syscall level; the
    // kernel may still fragment, but the parser sees a well-formed chunk).
    let mut frame = Vec::with_capacity(data.len() + 16);
    frame.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
    frame.extend_from_slice(data);
    frame.extend_from_slice(b"\r\n");
    w.write_all(&frame).await?;
    w.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Response header generation
// ---------------------------------------------------------------------------

fn build_headers(hostname: &str, rng: &mut impl Rng) -> Vec<String> {
    let apache = random_apache_version(rng);
    let mut h = vec![
        format!("Server: Apache/{apache} (FreeBSD) Server at {hostname} Port 80"),
        format!("Date: {}", http_date_now()),
        "Content-Type: text/html; charset=utf-8".to_string(),
        "Transfer-Encoding: chunked".to_string(),
        "Cache-Control: no-cache, no-store, must-revalidate".to_string(),
        "Pragma: no-cache".to_string(),
        "Connection: keep-alive".to_string(),
        format!("Set-Cookie: PHPSESSID={}; path=/; HttpOnly", random_hex(rng, 26)),
        "Vary: Accept-Encoding, User-Agent".to_string(),
    ];
    // Sprinkle in a few optional headers for variety.
    if rng.gen_bool(0.6) {
        h.push(format!("X-Powered-By: PHP/{}.{}.{}",
            rng.gen_range(7..=8), rng.gen_range(0..=4), rng.gen_range(0..=33)));
    }
    if rng.gen_bool(0.3) {
        h.push("X-Frame-Options: SAMEORIGIN".to_string());
    }
    if rng.gen_bool(0.3) {
        h.push("X-Content-Type-Options: nosniff".to_string());
    }
    if rng.gen_bool(0.2) {
        h.push("Strict-Transport-Security: max-age=31536000; includeSubDomains".to_string());
    }
    if rng.gen_bool(0.2) {
        h.push("Referrer-Policy: strict-origin-when-cross-origin".to_string());
    }
    h.shuffle(rng);
    h
}

fn random_apache_version(rng: &mut impl Rng) -> String {
    // Mirrors install.sh random_apache_version: 50/50 between 1.x and 2.x,
    // with realistic patch ceilings per minor branch.
    if rng.gen_bool(0.5) {
        format!("1.{}.{}", rng.gen_range(0..=3), rng.gen_range(0..=37))
    } else {
        match rng.gen_range(0..3) {
            0 => format!("2.0.{}", rng.gen_range(0..=65)),
            1 => format!("2.2.{}", rng.gen_range(0..=34)),
            _ => format!("2.4.{}", rng.gen_range(0..=67)),
        }
    }
}

fn random_hex(rng: &mut impl Rng, len: usize) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    (0..len).map(|_| HEX[rng.gen_range(0..16)] as char).collect()
}

// ---------------------------------------------------------------------------
// <head> element generation
// ---------------------------------------------------------------------------

fn generate_head_element(hostname: &str, rng: &mut impl Rng) -> String {
    match rng.gen_range(0..12) {
        0 => "<meta charset=\"utf-8\">".to_string(),
        1 => "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">".to_string(),
        2 => format!("<meta name=\"description\" content=\"{}\">", words(rng.gen_range(8..20), rng)),
        3 => format!("<meta name=\"keywords\" content=\"{}\">",
                    (0..rng.gen_range(4..10))
                        .map(|_| WORDS[rng.gen_range(0..WORDS.len())])
                        .collect::<Vec<_>>()
                        .join(", ")),
        4 => format!("<meta name=\"author\" content=\"{}\">", hostname),
        5 => format!("<meta name=\"generator\" content=\"WordPress {}.{}.{}\">",
                    rng.gen_range(5..=6), rng.gen_range(0..=9), rng.gen_range(0..=9)),
        6 => format!("<meta property=\"og:title\" content=\"{}\">", title_case(&words(rng.gen_range(3..7), rng))),
        7 => format!("<title>{}</title>", title_case(&words(rng.gen_range(2..6), rng))),
        8 => format!("<link rel=\"stylesheet\" href=\"/wp-content/themes/{}/{}?ver={}.{}.{}\">",
                    WP_THEMES[rng.gen_range(0..WP_THEMES.len())],
                    CSS_LIBS[rng.gen_range(0..CSS_LIBS.len())],
                    rng.gen_range(1..=6), rng.gen_range(0..=9), rng.gen_range(0..=20)),
        9 => format!("<link rel=\"icon\" type=\"image/png\" href=\"/favicon-{}.png\">",
                    [16, 32, 96, 192][rng.gen_range(0..4)]),
        10 => format!("<script src=\"/wp-includes/js/{}?ver={}.{}.{}\"></script>",
                    JS_LIBS[rng.gen_range(0..JS_LIBS.len())],
                    rng.gen_range(1..=4), rng.gen_range(0..=9), rng.gen_range(0..=30)),
        _ => format!("<script src=\"/wp-content/plugins/{}/assets/js/{}\"></script>",
                    WP_PLUGINS[rng.gen_range(0..WP_PLUGINS.len())],
                    JS_LIBS[rng.gen_range(0..JS_LIBS.len())]),
    }
}

// ---------------------------------------------------------------------------
// <body> element generation
// ---------------------------------------------------------------------------

fn generate_body_element(rng: &mut impl Rng) -> String {
    match rng.gen_range(0..10) {
        0 => format!("<h2>{}</h2>\n", title_case(&words(rng.gen_range(3..8), rng))),
        1 => format!("<p>{}</p>\n", capitalise(&words(rng.gen_range(20..60), rng))),
        2 => format!("<div class=\"{}\">{}</div>\n",
                    CSS_CLASSES[rng.gen_range(0..CSS_CLASSES.len())],
                    capitalise(&words(rng.gen_range(10..30), rng))),
        3 => {
            let n = rng.gen_range(3..8);
            let items: Vec<String> = (0..n)
                .map(|_| format!("  <li>{}</li>", capitalise(&words(rng.gen_range(2..6), rng))))
                .collect();
            format!("<ul>\n{}\n</ul>\n", items.join("\n"))
        }
        4 => format!("<a href=\"{}\">{}</a>\n",
                    URL_PATHS[rng.gen_range(0..URL_PATHS.len())],
                    title_case(&words(rng.gen_range(2..5), rng))),
        5 => format!("<img src=\"/uploads/{}.jpg\" alt=\"{}\" width=\"{}\" height=\"{}\">\n",
                    random_hex(rng, 12),
                    words(rng.gen_range(2..5), rng),
                    [320, 480, 640, 800, 1024][rng.gen_range(0..5)],
                    [240, 360, 480, 600, 768][rng.gen_range(0..5)]),
        6 => format!("<blockquote>{}</blockquote>\n", capitalise(&words(rng.gen_range(10..25), rng))),
        7 => format!("<article class=\"post-{}\"><h3>{}</h3><p>{}</p></article>\n",
                    rng.gen_range(100..9999),
                    title_case(&words(rng.gen_range(3..7), rng)),
                    capitalise(&words(rng.gen_range(15..40), rng))),
        8 => format!("<!-- {} -->\n", words(rng.gen_range(3..10), rng)),
        _ => format!("<section><h2>{}</h2><p>{}</p><p>{}</p></section>\n",
                    title_case(&words(rng.gen_range(2..5), rng)),
                    capitalise(&words(rng.gen_range(15..30), rng)),
                    capitalise(&words(rng.gen_range(15..30), rng))),
    }
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

fn words(n: usize, rng: &mut impl Rng) -> String {
    (0..n)
        .map(|_| WORDS[rng.gen_range(0..WORDS.len())])
        .collect::<Vec<_>>()
        .join(" ")
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => {
            let mut r = c.to_uppercase().collect::<String>();
            r.push_str(chars.as_str());
            r.push('.');
            r
        }
        None => String::new(),
    }
}

fn title_case(s: &str) -> String {
    s.split_whitespace()
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn jittered(base_ms: u64, jitter_ms: u64, rng: &mut impl Rng) -> Duration {
    if jitter_ms == 0 { return Duration::from_millis(base_ms); }
    Duration::from_millis(base_ms.saturating_add(rng.gen_range(0..=jitter_ms)))
}

// ---------------------------------------------------------------------------
// Date formatting (no chrono / time / httpdate dependency)
// ---------------------------------------------------------------------------

/// Current UTC time formatted per RFC 7231 §7.1.1.1:
///   "Sun, 06 Nov 1994 08:49:37 GMT"
///
/// We avoid pulling in chrono or httpdate for this single use - it would
/// add hundreds of KB to the binary.  The Gregorian-to-civil algorithm is
/// well-defined (Howard Hinnant, "date" library, 2013) and gives correct
/// results from 1970 through year 5000+.
fn http_date_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_http_date(secs)
}

fn format_http_date(unix_secs: u64) -> String {
    let days  = unix_secs / 86400;
    let stoday= unix_secs % 86400;
    let h     = stoday / 3600;
    let m     = (stoday / 60) % 60;
    let s     = stoday % 60;

    // 1970-01-01 was a Thursday.  Index 0 = Sunday.
    let day_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let dow = ((days + 4) % 7) as usize;

    let (year, month, day) = civil_from_days(days as i64);
    let month_names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        day_names[dow],
        day,
        month_names[(month - 1) as usize],
        year,
        h, m, s
    )
}

/// Hinnant 2013: Gregorian calendar serial-day conversion.
/// Input: days since 1970-01-01.  Output: (year, month [1..12], day [1..31]).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u64;
    let yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    let y   = (yoe as i64) + era * 400;
    let doy = doe - (365*yoe + yoe/4 - yoe/100);
    let mp  = (5*doy + 2) / 153;
    let d   = (doy - (153*mp + 2)/5 + 1) as u32;
    let m   = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y   = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
