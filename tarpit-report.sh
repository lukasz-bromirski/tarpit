#!/bin/sh
# tarpit-report.sh — daily HTML report from /var/log/tarpit.log entries
# v0.11.0
# Usage:
#   sh tarpit-report.sh [log_file] [output_file] [top_n]   generate report
#   sh tarpit-report.sh --update-db                         download GeoIP CSVs
# Defaults: /var/log/tarpit.log  →  tarpit-report-YYYY-MM-DD.html  top_n=20
#
# IP → ASN/org/country resolution is done OFFLINE against local CSV copies of
# the GeoLite2 databases from sapics/ip-location-db — no whois network calls.
# Run "sh tarpit-report.sh --update-db" once (and periodically, e.g. weekly via
# cron) to download/refresh the CSVs into ~/.cache/tarpit-geoip/.

# ── GeoIP data (local CSV copies of GeoLite2 from sapics/ip-location-db) ──────
GEOIP_DIR="${HOME}/.cache/tarpit-geoip"
ASN_CSV4="${GEOIP_DIR}/geolite2-asn-ipv4.csv"
ASN_CSV6="${GEOIP_DIR}/geolite2-asn-ipv6.csv"
CC_CSV4="${GEOIP_DIR}/geolite2-country-ipv4.csv"
CC_CSV6="${GEOIP_DIR}/geolite2-country-ipv6.csv"
GEOIP_BASE="https://raw.githubusercontent.com/sapics/ip-location-db/main"

# Download / refresh the local GeoLite2 CSVs.  ASN files are the ones you
# asked for; the country files are pulled too so the report's CC badge keeps
# working (the ASN DB has no country field).  Country is best-effort: if it
# fails, lookups still work and CC just shows "??".
update_geoip_db() {
    mkdir -p "$GEOIP_DIR" || return 1
    _dl() {  # url dest [required]
        _u="$1"; _d="$2"; _req="${3:-0}"; _tmp="${_d}.tmp.$$"
        echo "  fetching $(basename "$_d") ..." >&2
        if command -v fetch >/dev/null 2>&1; then
            fetch -q -o "$_tmp" "$_u" 2>/dev/null
        elif command -v curl >/dev/null 2>&1; then
            curl -fsSL -o "$_tmp" "$_u"
        else
            echo "ERROR: need fetch(1) or curl(1) to download GeoIP data" >&2
            return 2
        fi
        if [ $? -ne 0 ] || [ ! -s "$_tmp" ]; then
            rm -f "$_tmp"
            echo "    FAILED: $_u" >&2
            [ "$_req" = "1" ] && return 1
            return 0
        fi
        mv "$_tmp" "$_d"
    }
    _dl "${GEOIP_BASE}/geolite2-asn/geolite2-asn-ipv4.csv"        "$ASN_CSV4" 1 || return 1
    _dl "${GEOIP_BASE}/geolite2-asn/geolite2-asn-ipv6.csv"        "$ASN_CSV6" 0
    _dl "${GEOIP_BASE}/geolite2-country/geolite2-country-ipv4.csv" "$CC_CSV4" 0
    _dl "${GEOIP_BASE}/geolite2-country/geolite2-country-ipv6.csv" "$CC_CSV6" 0
    echo "GeoIP DB updated in ${GEOIP_DIR}:" >&2
    ls -la "$GEOIP_DIR" >&2
}

# --update-db must be handled BEFORE the log-file validation below, since
# downloading the DB doesn't need (and shouldn't require) a log file.
if [ "${1:-}" = "--update-db" ]; then
    update_geoip_db
    exit $?
fi

LOG_FILE="${1:-/var/log/tarpit.log}"
TODAY=$(date '+%Y-%m-%d')
HOST=$(hostname)
OUT_FILE="${2:-tarpit-report-${HOST}-${TODAY}.html}"
TOP_N="${3:-20}"

# ── 1. Validate input ─────────────────────────────────────────────────────────
if [ ! -f "$LOG_FILE" ]; then
    echo "Error: log file '$LOG_FILE' not found." >&2
    exit 1
fi

# ── 2. Parse today's entries ──────────────────────────────────────────────────
# Match the tarpit syslog tag with the PID bracket OPTIONAL: some hosts log
# "hostname tarpit[56199]: ..." and others "hostname tarpit: ..." depending on
# whether syslog attaches a PID.  Anchoring on the literal "tarpit[" (as older
# versions did) silently found zero entries on the no-PID hosts.
DATE_PREFIX=$(date '+%b %e')
TARPIT_RE='tarpit(\[[0-9]+\])?:'
ENTRIES=$(grep -E "$TARPIT_RE" "$LOG_FILE" | grep "^${DATE_PREFIX}")   # today
[ -z "$ENTRIES" ] && ENTRIES=$(grep -E "$TARPIT_RE" "$LOG_FILE")       # any date, still tagged
# Last resort: raw payload lines with no syslog tag at all (daemon file-logging).
# These can't be date-filtered, so this yields all-time data — fix the host's
# logging to route through syslog if you want a true daily window.
[ -z "$ENTRIES" ] && ENTRIES=$(grep 'service=' "$LOG_FILE" | grep 'src_ip=')
if [ -z "$ENTRIES" ]; then
    echo "No tarpit entries found in $LOG_FILE" >&2
    exit 0
fi

# ── 3. Collect unique IPs ─────────────────────────────────────────────────────
ALL_IPS=$(echo "$ENTRIES" | grep -oE 'src_ip=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
    sed 's/src_ip=//' | sort -u)

# ══════════════════════════════════════════════════════════════════════════════
# OFFLINE GEOIP RESOLUTION (GeoLite2 CSVs from sapics/ip-location-db)
#
# Replaces the old per-IP whois calls.  In ONE awk pass per CSV we resolve all
# of today's unique IPs at once using a sorted-merge against the range-based
# CSVs (format: start_ip,end_ip,asn,as_name  /  start_ip,end_ip,country_code).
#
# Output: a small temp "lookup file" with one TAB-separated line per IP:
#     <ip>\t<org>\t<cc>\t<cidr>
# where org = "AS<n> <name>", cc = 2-letter country (or ?? ), cidr = the
# covering prefix derived from the matched range.  The whois_org/cc/cidr
# accessors below read this file, so everything downstream is unchanged.
#
# NOTE: the log parser above only extracts IPv4 src_ip, so only the IPv4 CSVs
# are consulted.  The IPv6 CSVs are downloaded by --update-db and sit ready for
# when IPv6 log parsing is added.
# ══════════════════════════════════════════════════════════════════════════════

if [ ! -f "$ASN_CSV4" ]; then
    echo "Error: GeoIP ASN database not found at $ASN_CSV4" >&2
    echo "       Download it once with:  sh $0 --update-db" >&2
    exit 1
fi

LOOKUP_FILE=$(mktemp -t tarpit-geoip.XXXXXX) || { echo "mktemp failed" >&2; exit 1; }
IP_TMP=$(mktemp -t tarpit-ips.XXXXXX)       || { echo "mktemp failed" >&2; exit 1; }
trap 'rm -f "$LOOKUP_FILE" "$IP_TMP"' EXIT INT TERM

# Sorted "ipint ip" list — sorted-merge against the (start-ascending) CSV needs
# the target IPs in ascending integer order too.
echo "$ALL_IPS" | awk -F. 'NF==4 && $1!="" {
        printf "%d %s\n", ($1*16777216)+($2*65536)+($3*256)+$4, $0
    }' | sort -n > "$IP_TMP"

echo "Resolving $(wc -l < "$IP_TMP" | tr -d ' ') IP(s) against local GeoLite2 CSVs..." >&2

# Single awk: load sorted IPs, sorted-merge over ASN CSV, then over country CSV,
# emit one line per IP.  CC file is optional (passed as "" when absent).
[ -f "$CC_CSV4" ] && _CC_ARG="$CC_CSV4" || _CC_ARG=""

awk -v ipfile="$IP_TMP" -v asncsv="$ASN_CSV4" -v cccsv="$_CC_ARG" '
function ip2int(s,   a) { split(s,a,"."); return a[1]*16777216 + a[2]*65536 + a[3]*256 + a[4] }
function net2str(v) {
    return int(v/16777216)%256 "." int(v/65536)%256 "." int(v/256)%256 "." v%256
}
# Largest power-of-2 CIDR block, aligned at the range start, that fits the
# range size.  Exact for single-CIDR ranges (the common case); a sane covering
# approximation otherwise.
function cidr_of(s, e,   size, plen, t, blk, i, net) {
    size = e - s + 1; plen = 32; t = size
    while (t > 1) { t = int(t/2); plen-- }
    blk = 1; for (i = 0; i < 32 - plen; i++) blk *= 2
    net = int(s/blk) * blk
    return net2str(net) "/" plen
}
BEGIN {
    # 1) load sorted target IPs
    n = 0
    while ((getline line < ipfile) > 0) {
        split(line, f, " "); n++; tint[n] = f[1] + 0; tip[n] = f[2]
    }
    close(ipfile)
    if (n == 0) exit 0

    # 2) ASN merge → org[], cidr[]
    j = 1
    while ((getline row < asncsv) > 0) {
        sub(/\r$/, "", row)
        m = split(row, c, ",")
        if (m < 3) continue
        s = ip2int(c[1]); e = ip2int(c[2])
        while (j <= n && tint[j] < s) j++           # IPs in gaps stay unresolved
        if (j > n) break
        if (tint[j] <= e) {
            name = (m >= 4) ? c[4] : ""
            for (i = 5; i <= m; i++) name = name "," c[i]   # name may contain commas
            gsub(/^"|"$/, "", name); gsub(/[|\t]/, " ", name)
            asn = c[3] + 0
            cd = cidr_of(s, e)
            org = (asn > 0) ? ("AS" asn (name != "" ? " " name : "")) : (name != "" ? name : "unknown")
            while (j <= n && tint[j] <= e) { orgv[tip[j]] = org; cidrv[tip[j]] = cd; j++ }
            if (j > n) break
        }
    }
    close(asncsv)

    # 3) Country merge → cc[]  (optional)
    if (cccsv != "") {
        k = 1
        while ((getline row < cccsv) > 0) {
            sub(/\r$/, "", row)
            m = split(row, c, ",")
            if (m < 3) continue
            s = ip2int(c[1]); e = ip2int(c[2])
            while (k <= n && tint[k] < s) k++
            if (k > n) break
            if (tint[k] <= e) {
                code = c[3]; gsub(/^"|"$/, "", code); gsub(/[|\t ]/, "", code)
                code = toupper(substr(code, 1, 2))
                while (k <= n && tint[k] <= e) { ccv[tip[k]] = code; k++ }
                if (k > n) break
            }
        }
        close(cccsv)
    }

    # 4) emit one line per IP (original sorted order is fine)
    for (i = 1; i <= n; i++) {
        ip = tip[i]
        o  = (ip in orgv)  ? orgv[ip]  : "unknown"
        cc = (ip in ccv)   ? ccv[ip]   : "??"
        cd = (ip in cidrv) ? cidrv[ip] : (ip "/32")
        if (cc == "") cc = "??"
        printf "%s\t%s\t%s\t%s\n", ip, o, cc, cd
    }
}
' < /dev/null > "$LOOKUP_FILE"

echo "GeoIP resolution done." >&2

# Accessor: print field F (1=org 2=cc 3=cidr) for an IP from the lookup file.
# Contract identical to the old whois_* functions, so downstream is unchanged.
_cache_field() {
    awk -F'\t' -v ip="$1" -v f="$2" '
        $1 == ip { print $(f + 1); hit = 1; exit }
        END { if (!hit) { if (f == 1) print "unknown"; else if (f == 2) print "??"; else print ip "/32" } }
    ' "$LOOKUP_FILE"
}
whois_org()  { _cache_field "$1" 1; }
whois_cc()   { _cache_field "$1" 2; }
whois_cidr() { _cache_field "$1" 3; }

# ── 5. Collect unique services ────────────────────────────────────────────────
SERVICES=$(echo "$ENTRIES" | grep -oE 'service=[a-zA-Z0-9_-]+' | sed 's/service=//' | sort -u)

# ── 6. Per-IP duration stats via awk ─────────────────────────────────────────
build_ip_stats() {
    # $1 = filtered entries for this scope
    echo "$1" | \
        grep -oE 'src_ip=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ src_port=[0-9]+ duration_ms=[0-9]+' | \
        sed 's/src_ip=//;s/ src_port=[0-9]*//;s/ duration_ms=/ /' | \
        sort | \
        awk '
        {
            ip=$1; ms=$2; count[ip]++; sum[ip]+=ms
            if(!(ip in minv)||ms<minv[ip]) minv[ip]=ms
            if(!(ip in maxv)||ms>maxv[ip]) maxv[ip]=ms
        }
        END { for(ip in count) print count[ip], ip, minv[ip], maxv[ip], int(sum[ip]/count[ip]), sum[ip] }
        ' | sort -rn
}

# ── 7. Build JSON ─────────────────────────────────────────────────────────────
build_json_data() {
    printf '{\n'
    FIRST_SVC=1
    for SVC in $SERVICES; do
        SVC_ENTRIES=$(echo "$ENTRIES" | grep "service=${SVC} ")
        TOTAL=$(echo "$SVC_ENTRIES" | wc -l | tr -d ' ')

        IP_JSON=$(build_ip_stats "$SVC_ENTRIES" | while read -r COUNT IP MIN_MS MAX_MS AVG_MS TOTAL_MS; do
            ORG=$(whois_org  "$IP" | sed 's/"/\\"/g')
            CC=$( whois_cc   "$IP")
            CIDR=$(whois_cidr "$IP" | sed 's/"/\\"/g')
            printf '{"ip":"%s","count":%d,"min_ms":%d,"max_ms":%d,"avg_ms":%d,"total_ms":%d,"org":"%s","cc":"%s","cidr":"%s"},\n' \
                "$IP" "$COUNT" "$MIN_MS" "$MAX_MS" "$AVG_MS" "$TOTAL_MS" "$ORG" "$CC" "$CIDR"
        done | sed '$ s/,$//')

        REASON_DATA=$(echo "$SVC_ENTRIES" | grep -oE 'reason=[a-zA-Z0-9_]+' | \
            sed 's/reason=//' | sort | uniq -c | sort -rn | \
            awk '{printf "{\"reason\":\"%s\",\"count\":%d},\n",$2,$1}')
        REASON_DATA=$(echo "$REASON_DATA" | sed '$ s/,$//')

        AVG_DUR=$(echo "$SVC_ENTRIES" | grep -oE 'duration_ms=[0-9]+' | sed 's/duration_ms=//' | \
            awk '{s+=$1;c++} END{if(c>0) printf "%d",int(s/c); else print "0"}')

        [ $FIRST_SVC -eq 0 ] && printf ',\n'
        printf '  "%s": { "total": %d, "avg_ms": %d, "ips": [%s], "reasons": [%s] }' \
            "$SVC" "$TOTAL" "$AVG_DUR" "$IP_JSON" "$REASON_DATA"
        FIRST_SVC=0
    done
    printf '\n}\n'
}

JSON_DATA=$(build_json_data)

# ── 8. Top-N abusers (all services) ──────────────────────────────────────────
# Candidate pool = UNION of top-N-by-hits and top-N-by-total-time-wasted,
# deduped by IP.  Emitting the union (instead of just head -N by count) lets
# the client-side sort toggle show the TRUE top-N for either metric — an IP
# that ranks high on time wasted but low on hit count is still in the data.
# The JS slices this pool to TOP_N by whichever key is active, so each view
# still shows exactly N rows.  Columns: count ip min max avg total_ms
TOP_POOL_RAW=$(build_ip_stats "$ENTRIES")
TOP_POOL=$(
    {
        echo "$TOP_POOL_RAW" | head -"$TOP_N"                   # top-N by count (col 1)
        echo "$TOP_POOL_RAW" | sort -k6,6 -rn | head -"$TOP_N"  # top-N by total_ms (col 6)
    } | awk 'NF && !seen[$2]++'   # drop blanks, dedup by IP (field 2)
)

TOP_JSON=$(echo "$TOP_POOL" | \
    while read -r COUNT IP MIN_MS MAX_MS AVG_MS TOTAL_MS; do
        [ -z "$IP" ] && continue
        ORG=$(whois_org  "$IP" | sed 's/"/\\"/g')
        CC=$( whois_cc   "$IP")
        CIDR=$(whois_cidr "$IP" | sed 's/"/\\"/g')
        SVCS=$(echo "$ENTRIES" | grep "src_ip=${IP} " | \
            grep -oE 'service=[a-zA-Z0-9_-]+' | sed 's/service=//' | sort -u | \
            tr '\n' ',' | sed 's/,$//')
        printf '{"ip":"%s","count":%d,"min_ms":%d,"max_ms":%d,"avg_ms":%d,"total_ms":%d,"org":"%s","cc":"%s","cidr":"%s","services":"%s"},\n' \
            "$IP" "$COUNT" "$MIN_MS" "$MAX_MS" "$AVG_MS" "$TOTAL_MS" "$ORG" "$CC" "$CIDR" "$SVCS"
    done | sed '$ s/,$//')

# ── 9. Totals ─────────────────────────────────────────────────────────────────
TOTAL_HITS=$(echo "$ENTRIES" | wc -l | tr -d ' ')
UNIQUE_IPS=$(echo "$ALL_IPS" | wc -l | tr -d ' ')
SVC_COUNT=$(echo "$SERVICES" | wc -l | tr -d ' ')
TOTAL_MS=$(echo "$ENTRIES" | grep -oE 'duration_ms=[0-9]+' | sed 's/duration_ms=//' | \
    awk '{s+=$1} END{printf "%d",s}')

# ── 10. Emit HTML ─────────────────────────────────────────────────────────────
cat > "$OUT_FILE" << HTMLEOF
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>tarpit report for $HOST at ${TODAY}</title>
<style>
:root,[data-theme="light"]{
  --bg:#f7f6f2;--surface:#f9f8f5;--surface-2:#fbfbf9;--surface-off:#edeae5;
  --border:#d4d1ca;--divider:#dcd9d5;
  --text:#28251d;--muted:#7a7974;--faint:#bab9b4;
  --primary:#01696f;--primary-h:#0c4e54;--primary-hi:#cedcd8;
  --warning:#964219;--warn-hi:#ddcfc6;
  --error:#a12c7b;--success:#437a22;
  --shadow-sm:0 1px 2px rgba(40,37,29,.06);
  --shadow-md:0 4px 12px rgba(40,37,29,.09);
  --r-sm:.375rem;--r-md:.5rem;--r-lg:.75rem;--r-xl:1rem;
}
[data-theme="dark"]{
  --bg:#171614;--surface:#1c1b19;--surface-2:#201f1d;--surface-off:#22211f;
  --border:#393836;--divider:#262523;
  --text:#cdccca;--muted:#797876;--faint:#5a5957;
  --primary:#4f98a3;--primary-h:#227f8b;--primary-hi:#313b3b;
  --warning:#bb653b;--warn-hi:#564942;
  --error:#d163a7;--success:#6daa45;
  --shadow-sm:0 1px 2px rgba(0,0,0,.22);
  --shadow-md:0 4px 14px rgba(0,0,0,.32);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
body{min-height:100vh;font-family:'Inter',system-ui,sans-serif;font-size:16px;line-height:1.6;color:var(--text);background:var(--bg)}
h2{font-size:clamp(1.125rem,1rem+.75vw,1.5rem);line-height:1.2;font-weight:600}
.container{max-width:1140px;margin-inline:auto;padding-inline:clamp(1rem,4vw,2.5rem)}
.page-header{background:var(--surface);border-bottom:1px solid var(--border);padding:1.25rem 0;position:sticky;top:0;z-index:100}
.page-header-inner{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.logo{display:flex;align-items:center;gap:.625rem;text-decoration:none;color:var(--text)}
.logo-label{font-weight:700;font-size:1.1rem;letter-spacing:-.02em}
.logo-date{font-size:.8125rem;color:var(--muted);margin-left:.25rem;font-weight:400}
.theme-btn{background:none;border:1px solid var(--border);color:var(--muted);width:36px;height:36px;border-radius:var(--r-md);display:grid;place-items:center;cursor:pointer;transition:background .18s,color .18s;flex-shrink:0}
.theme-btn:hover{background:var(--surface-off);color:var(--text)}
.kpi-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:1rem;padding:2rem 0 1.5rem}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:1.25rem 1.5rem;box-shadow:var(--shadow-sm)}
.kpi-label{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:.4rem}
.kpi-value{font-size:clamp(1.75rem,1rem+2vw,2.5rem);font-weight:700;line-height:1;font-variant-numeric:tabular-nums;color:var(--primary)}
.kpi-sub{font-size:.75rem;color:var(--faint);margin-top:.3rem}
.section{padding:1.5rem 0}
.section-title{font-size:.6875rem;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:1.25rem;display:flex;align-items:center;gap:.5rem}
.section-title::after{content:'';flex:1;height:1px;background:var(--divider)}
.tabs{display:flex;gap:.375rem;flex-wrap:wrap;margin-bottom:1.5rem}
.tab{padding:.4375rem 1rem;border-radius:9999px;font-size:.8125rem;font-weight:500;border:1px solid var(--border);background:none;color:var(--muted);cursor:pointer;transition:background .18s,color .18s,border-color .18s}
.tab:hover{background:var(--surface-off);color:var(--text)}
.tab.active{background:var(--primary);border-color:var(--primary);color:#fff}
.tab.special{border-style:dashed}
.tab.special.active{background:var(--warning);border-color:var(--warning);border-style:solid;color:#fff}
.panel{display:none}.panel.active{display:block}
.panel-grid{display:grid;grid-template-columns:2fr 1fr;gap:1.25rem}
@media(max-width:780px){.panel-grid{grid-template-columns:1fr}}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:1.25rem;box-shadow:var(--shadow-sm);overflow:hidden}
.card-title{font-size:.75rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:1rem}
.ip-table{width:100%;border-collapse:collapse;font-size:.8125rem}
.ip-table th{text-align:left;font-size:.625rem;text-transform:uppercase;letter-spacing:.07em;color:var(--faint);padding:.375rem .5rem .5rem 0;border-bottom:1px solid var(--divider);font-weight:500;white-space:nowrap}
.ip-table th:first-child{padding-left:0}
.ip-table td{padding:.45rem .5rem .45rem 0;border-bottom:1px solid var(--divider);vertical-align:middle}
.ip-table td:first-child{padding-left:0}
.ip-table tr:last-child td{border-bottom:none}
.ip-col{font-family:ui-monospace,'Cascadia Code','Fira Code',monospace;font-size:.8125rem;color:var(--text);white-space:nowrap}
/* CIDR shown as subtle sub-line under the IP */
.ip-cidr{font-size:.6875rem;color:var(--faint);display:block;margin-top:.1rem;font-family:ui-monospace,'Cascadia Code','Fira Code',monospace}
.org-col{font-size:.75rem;color:var(--muted);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cc-badge{display:inline-block;font-size:.625rem;font-weight:600;letter-spacing:.04em;padding:.1rem .35rem;border-radius:var(--r-sm);background:var(--surface-off);color:var(--muted);border:1px solid var(--border);margin-left:.3rem;vertical-align:middle}
.num-col{text-align:right;font-weight:600;color:var(--primary);font-variant-numeric:tabular-nums;white-space:nowrap;padding-right:.25rem}
.num-head{text-align:right}
.total-col{color:var(--warning)}
.ip-table th.sort-active{color:var(--primary);font-weight:700}
.sort-toggle{display:inline-flex;margin-left:auto;border:1px solid var(--border);border-radius:var(--r-sm);overflow:hidden}
.sort-toggle button{font:inherit;font-size:.625rem;text-transform:uppercase;letter-spacing:.07em;font-weight:600;color:var(--muted);background:var(--surface);border:0;padding:.25rem .625rem;cursor:pointer;line-height:1.6}
.sort-toggle button+button{border-left:1px solid var(--border)}
.sort-toggle button.active{background:var(--primary);color:#fff}
.dur-col{text-align:right;font-size:.75rem;color:var(--muted);white-space:nowrap;font-variant-numeric:tabular-nums}
.dur-range{display:flex;gap:.25rem;justify-content:flex-end;align-items:baseline}
.dur-avg{font-weight:600;color:var(--text)}
.dur-minmax{color:var(--faint);font-size:.6875rem}
.bar-wrap{padding-left:.75rem;width:100px}
.bar-bg{background:var(--surface-off);border-radius:9999px;height:5px;overflow:hidden}
.bar-fill{height:100%;border-radius:9999px;background:var(--primary);transition:width .5s cubic-bezier(.16,1,.3,1)}
.svc-tags{display:flex;gap:.25rem;flex-wrap:wrap}
.svc-tag{font-size:.625rem;font-weight:600;padding:.1rem .4rem;border-radius:var(--r-sm);border:1px solid var(--border);color:var(--muted);background:var(--surface-2);white-space:nowrap}
.reasons{display:flex;flex-direction:column;gap:.5rem}
.reason-item{display:flex;align-items:center;gap:.75rem;padding:.5rem .875rem;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r-md);font-size:.8125rem}
.reason-label{color:var(--text);font-weight:500;flex:1}
.reason-count{font-weight:700;color:var(--primary);font-variant-numeric:tabular-nums}
.reason-bar{width:60px;flex-shrink:0}
.stats-strip{display:flex;gap:1.5rem;flex-wrap:wrap;margin-bottom:1rem}
.stat{font-size:.8125rem;color:var(--muted)}.stat strong{color:var(--text);font-weight:600}
.rank-num{font-size:.6875rem;font-weight:700;color:var(--faint);text-align:center;width:1.5rem;flex-shrink:0}
.page-footer{border-top:1px solid var(--divider);margin-top:3rem;padding:1.5rem 0;font-size:.75rem;color:var(--faint);text-align:center}
@media(max-width:480px){.kpi-value{font-size:1.75rem}.card{padding:1rem}.bar-wrap{display:none}}
</style>
</head>
<body>

<header class="page-header">
  <div class="container">
    <div class="page-header-inner">
      <a class="logo" href="#">
        <svg width="28" height="28" viewBox="0 0 28 28" fill="none" aria-label="Tarpit">
          <rect width="28" height="28" rx="7" fill="var(--primary)"/>
          <path d="M8 14 Q14 7 20 14 Q14 21 8 14Z" fill="none" stroke="#fff" stroke-width="1.75"/>
          <circle cx="14" cy="14" r="2.5" fill="#fff"/>
          <line x1="14" y1="7" x2="14" y2="5" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>
          <line x1="14" y1="21" x2="14" y2="23" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
        <span class="logo-label">tarpit report for <b>$HOST</b> at <b>${TODAY}</b></span></span>
      </a>
      <button class="theme-btn" data-theme-toggle aria-label="Toggle theme">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
        </svg>
      </button>
    </div>
  </div>
</header>

<main>
  <div class="container">
    <div class="kpi-row" id="kpi-row"></div>
    <div class="section">
      <div class="section-title">By Service
        <span class="sort-toggle" id="sort-toggle">
          <button type="button" data-sort="count" class="active">Hits</button>
          <button type="button" data-sort="total_ms">Time wasted</button>
        </span>
      </div>
      <div class="tabs" id="tabs"></div>
      <div id="panels"></div>
    </div>
  </div>
</main>

<footer class="page-footer">
  <div class="container">
    Generated from <code>${LOG_FILE}</code> · ${TODAY} · GeoLite2 DB: <code>${GEOIP_DIR}/</code>
  </div>
</footer>

<script>
const DATA     = ${JSON_DATA};
const TOP_DATA = [${TOP_JSON}];
const TOP_N    = ${TOP_N};
const TOTAL_HITS = ${TOTAL_HITS};
const UNIQUE_IPS = ${UNIQUE_IPS};
const SVC_COUNT  = ${SVC_COUNT};
const TOTAL_MS   = ${TOTAL_MS};

function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') }
function fmtMs(ms){
  if(ms>=60000) return (ms/60000).toFixed(1)+'m'
  if(ms>=1000)  return (ms/1000).toFixed(1)+'s'
  return ms+'ms'
}

// KPIs
const kpiRow = document.getElementById('kpi-row')
const totalWastedMin = Math.round(TOTAL_MS/60000)
;[
  {label:'Total Hits',    value:TOTAL_HITS,       sub:'connections today'},
  {label:'Unique IPs',   value:UNIQUE_IPS,        sub:'distinct sources'},
  {label:'Services Hit', value:SVC_COUNT,         sub:'distinct services'},
  {label:'Time Wasted',  value:totalWastedMin,    sub:'attacker-minutes burned', suffix:'m'},
].forEach(k=>{
  kpiRow.insertAdjacentHTML('beforeend',
    '<div class="kpi"><div class="kpi-label">'+k.label+'</div>'+
    '<div class="kpi-value" data-target="'+k.value+'" data-suffix="'+(k.suffix||'')+'">0</div>'+
    '<div class="kpi-sub">'+k.sub+'</div></div>')
})
document.querySelectorAll('.kpi-value').forEach(el=>{
  const target=parseInt(el.dataset.target,10), suffix=el.dataset.suffix||''
  const start=performance.now(), dur=700
  const step=now=>{ const t=Math.min((now-start)/dur,1),e=1-Math.pow(1-t,3); el.textContent=Math.round(e*target)+suffix; if(t<1)requestAnimationFrame(step) }
  requestAnimationFrame(step)
})

// ── Sort state ───────────────────────────────────────────────────────────
// Which metric IP tables are ordered by: 'count' = hit count (default,
// matches historical behaviour); 'total_ms' = total time wasted per IP.
let sortKey='count'
const SORT_LABEL={count:'hits',total_ms:'time wasted'}
function sortIps(ips){return ips.slice().sort((a,b)=>(b[sortKey]||0)-(a[sortKey]||0))}

// IP table builder.  Sorts by the active sortKey, scales the inline bar to
// that same metric (so the bar stays monotonic top-to-bottom), and shows
// both Hits and Total-wasted columns.
function ipRows(ips, showServices){
  if(!ips.length) return '<tr><td colspan="9" style="color:var(--faint);padding:.75rem 0">No data</td></tr>'
  const arr=sortIps(ips)
  const maxVal=arr.length?(arr[0][sortKey]||1):1
  return arr.map((r,i)=>{
    const pct=Math.round(((r[sortKey]||0)/maxVal)*100)
    // Show CIDR only when it differs from /32 (i.e. a real prefix was resolved)
    const cidrLabel = r.cidr && !r.cidr.endsWith('/32') ? '<span class="ip-cidr">'+esc(r.cidr)+'</span>' : ''
    const svcTags = showServices && r.services
      ? '<div class="svc-tags">'+r.services.split(',').map(s=>'<span class="svc-tag">'+esc(s)+'</span>').join('')+'</div>'
      : ''
    return '<tr>'+
      (showServices?'<td class="rank-num">'+(i+1)+'</td>':'')+
      '<td class="ip-col">'+esc(r.ip)+'<span class="cc-badge">'+esc(r.cc)+'</span>'+cidrLabel+'</td>'+
      '<td class="org-col" title="'+esc(r.org)+'">'+esc(r.org)+'</td>'+
      (showServices?'<td>'+svcTags+'</td>':'')+
      '<td class="num-col">'+r.count+'</td>'+
      '<td class="dur-col"><div class="dur-range"><span class="dur-avg">~'+fmtMs(r.avg_ms)+'</span>'+
        '<span class="dur-minmax">'+fmtMs(r.min_ms)+'-'+fmtMs(r.max_ms)+'</span></div></td>'+
      '<td class="num-col total-col">'+fmtMs(r.total_ms!=null?r.total_ms:0)+'</td>'+
      '<td class="bar-wrap"><div class="bar-bg"><div class="bar-fill" style="width:'+pct+'%"></div></div></td>'+
    '</tr>'
  }).join('')
}
function ipTableHead(showServices){
  // Highlight whichever column is the active sort key.
  const hitsActive = sortKey==='count'    ? ' sort-active' : ''
  const timeActive = sortKey==='total_ms' ? ' sort-active' : ''
  return '<thead><tr>'+
    (showServices?'<th></th>':'')+
    '<th>IP / Prefix</th><th>Organisation</th>'+
    (showServices?'<th>Services</th>':'')+
    '<th class="num-head'+hitsActive+'">Hits</th>'+
    '<th class="num-head">Duration (avg · min-max)</th>'+
    '<th class="num-head'+timeActive+'">Total wasted</th>'+
    '<th class="bar-wrap"></th></tr></thead>'
}

// ── Tabs + panels (re-runnable so the sort toggle can re-render) ──────────
const tabsEl=document.getElementById('tabs'), panelsEl=document.getElementById('panels')
const services=Object.keys(DATA)
let currentSvc=services.length?services[0]:'__top__'

function buildServicePanel(svc){
  const d=DATA[svc]
  const tabBtn=document.createElement('button')
  tabBtn.className='tab'
  tabBtn.textContent=svc+' ('+d.total+')'
  tabBtn.dataset.svc=svc
  tabBtn.addEventListener('click',()=>activate(svc))
  tabsEl.appendChild(tabBtn)

  const maxReason=d.reasons.length?d.reasons[0].count:1
  const reasonHTML=d.reasons.map(r=>{
    const pct=Math.round((r.count/maxReason)*100)
    return '<div class="reason-item"><span class="reason-label">'+esc(r.reason)+'</span>'+
      '<div class="reason-bar"><div class="bar-bg"><div class="bar-fill" style="width:'+pct+'%"></div></div></div>'+
      '<span class="reason-count">'+r.count+'</span></div>'
  }).join('')||'<span style="color:var(--faint);font-size:.875rem">None</span>'

  const panel=document.createElement('div')
  panel.className='panel'
  panel.id='panel-'+svc
  panel.innerHTML=
    '<div class="stats-strip">'+
      '<span class="stat">Total hits: <strong>'+d.total+'</strong></span>'+
      '<span class="stat">Unique IPs: <strong>'+d.ips.length+'</strong></span>'+
      '<span class="stat">Avg duration: <strong>'+fmtMs(d.avg_ms)+'</strong></span>'+
    '</div>'+
    '<div class="panel-grid">'+
      '<div class="card"><div class="card-title">Source IPs</div>'+
        '<table class="ip-table">'+ipTableHead(false)+'<tbody>'+ipRows(d.ips,false)+'</tbody></table></div>'+
      '<div class="card"><div class="card-title">Disconnect Reasons</div>'+
        '<div class="reasons">'+reasonHTML+'</div></div>'+
    '</div>'
  panelsEl.appendChild(panel)
}

function buildTopPanel(){
  const topBtn=document.createElement('button')
  topBtn.className='tab special'
  topBtn.textContent='★ Top '+TOP_N+' Abusers'
  topBtn.dataset.svc='__top__'
  topBtn.addEventListener('click',()=>activate('__top__'))
  tabsEl.appendChild(topBtn)

  // TOP_DATA is the union pool (top-N-by-hits ∪ top-N-by-time).  Slice to
  // TOP_N by the ACTIVE key so the panel shows the true top-N for whichever
  // metric is selected.
  const topRows=sortIps(TOP_DATA).slice(0,TOP_N)
  const topPanel=document.createElement('div')
  topPanel.className='panel'
  topPanel.id='panel-__top__'
  topPanel.innerHTML=
    '<div class="stats-strip"><span class="stat">Top <strong>'+topRows.length+'</strong> IPs by '+SORT_LABEL[sortKey]+' across all services</span></div>'+
    '<div class="card"><div class="card-title">Top Abusers — All Services</div>'+
      '<table class="ip-table">'+ipTableHead(true)+'<tbody>'+ipRows(topRows,true)+'</tbody></table></div>'
  panelsEl.appendChild(topPanel)
}

function renderPanels(){
  tabsEl.innerHTML=''
  panelsEl.innerHTML=''
  services.forEach(svc=>buildServicePanel(svc))
  buildTopPanel()
  activate(currentSvc)
}

function activate(svc){
  currentSvc=svc
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.dataset.svc===svc))
  document.querySelectorAll('.panel').forEach(p=>p.classList.toggle('active',p.id==='panel-'+svc))
}

// ── Sort toggle ───────────────────────────────────────────────────────────
const sortToggleEl=document.getElementById('sort-toggle')
if(sortToggleEl){
  sortToggleEl.addEventListener('click',e=>{
    const b=e.target.closest('button[data-sort]'); if(!b||b.dataset.sort===sortKey) return
    sortKey=b.dataset.sort
    sortToggleEl.querySelectorAll('button[data-sort]').forEach(x=>
      x.classList.toggle('active',x.dataset.sort===sortKey))
    renderPanels()
  })
}

renderPanels()

// Theme toggle
;(function(){
  const btn=document.querySelector('[data-theme-toggle]'),root=document.documentElement
  let theme=root.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light')
  root.setAttribute('data-theme',theme)
  const sun='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>'
  const moon='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>'
  const sync=()=>{btn.innerHTML=theme==='dark'?sun:moon}; sync()
  btn.addEventListener('click',()=>{theme=theme==='dark'?'light':'dark';root.setAttribute('data-theme',theme);sync()})
})()
</script>
</body>
</html>
HTMLEOF

echo "Done: $(wc -l < "$OUT_FILE") lines"
