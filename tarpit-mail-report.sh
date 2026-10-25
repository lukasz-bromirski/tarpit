#!/bin/sh
# tarpit-mail-report.sh
# v0.14.0
# Generate the daily tarpit HTML report and email it to one recipient
# as a gzipped attachment.  Designed for cron on a FreeBSD host.
#
# Crontab entry (run as the unprivileged user who owns the script):
#
#   0 0 * * *   /home/szopen/tarpit-mail-report.sh
#

PATH="/usr/sbin:/usr/bin:/bin"
export PATH

set -u

# ---- configuration --------------------------------------------------------

TO="lukasz+tarpit@bromirski.net"
REPORT_CMD="/usr/local/bin/tarpit-report.sh"
LOG_FILE="/var/log/tarpit.log"       # passed as $1 to REPORT_CMD
SUBJECT_PREFIX="[tarpit]"

# ---- preflight ------------------------------------------------------------

[ -x "$REPORT_CMD" ] || { echo "ERROR: $REPORT_CMD not executable" >&2; exit 1; }
[ -r "$LOG_FILE"   ] || { echo "ERROR: $LOG_FILE not readable"    >&2; exit 1; }
command -v sendmail >/dev/null 2>&1 || { echo "ERROR: sendmail not found in PATH ($PATH)" >&2; exit 1; }
command -v openssl  >/dev/null 2>&1 || { echo "ERROR: openssl not found"  >&2; exit 1; }
command -v gzip     >/dev/null 2>&1 || { echo "ERROR: gzip not found"     >&2; exit 1; }

# ---- generate the report --------------------------------------------------

HOST_SHORT=$(hostname -s)
HOST_FULL=$(hostname)
TODAY=$(date +%Y-%m-%d)
DATE_HDR=$(date '+%a, %d %b %Y %H:%M:%S %z')

TMPDIR=$(mktemp -d -t tarpit-mail.XXXXXX) || { echo "mktemp -d failed" >&2; exit 1; }
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

HTML="$TMPDIR/tarpit-${HOST_SHORT}-${TODAY}.html"
GZ="$HTML.gz"

# tarpit-report.sh signature: sh tarpit-report.sh [log_file] [output_file] [top_n]
# IMPORTANT: it writes the HTML to its $2 (file), and prints only a
# one-line status ("Done: N lines") to stdout.  We pass our temp path
# as $2 and discard the stdout chatter.

if ! "$REPORT_CMD" "$LOG_FILE" "$HTML" >/dev/null; then
    rc=$?
    echo "ERROR: $REPORT_CMD failed (exit $rc)" >&2
    exit "$rc"
fi

# Sanity-check.  tarpit-report.sh exits 0 with no output file if today's
# log has zero tarpit entries — we treat that as nothing-to-mail.

if [ ! -s "$HTML" ]; then
    echo "ERROR: $HTML is missing or empty after running $REPORT_CMD" >&2
    echo "  Possible cause: no tarpit entries in $LOG_FILE for today" >&2
    exit 1
fi

gzip -c "$HTML" > "$GZ"

# ---- build & send the MIME message ----------------------------------------

BOUNDARY="tarpit_$(date +%s)_$$"
ATTACH_NAME=$(basename "$GZ")
FROM="tarpit@${HOST_FULL}"
SUBJECT="${SUBJECT_PREFIX} ${HOST_SHORT} report ${TODAY}"

{
    printf 'From: %s\r\n'           "$FROM"
    printf 'To: %s\r\n'             "$TO"
    printf 'Subject: %s\r\n'        "$SUBJECT"
    printf 'Date: %s\r\n'           "$DATE_HDR"
    printf 'MIME-Version: 1.0\r\n'
    printf 'Content-Type: multipart/mixed; boundary="%s"\r\n' "$BOUNDARY"
    printf '\r\n'

    printf -- '--%s\r\n' "$BOUNDARY"
    printf 'Content-Type: text/plain; charset=us-ascii\r\n'
    printf 'Content-Transfer-Encoding: 7bit\r\n'
    printf '\r\n'
    printf 'Daily tarpit report from %s.\r\n' "$HOST_FULL"
    printf 'See attached %s (gunzip to read).\r\n' "$ATTACH_NAME"
    printf '\r\n'

    printf -- '--%s\r\n' "$BOUNDARY"
    printf 'Content-Type: application/gzip; name="%s"\r\n' "$ATTACH_NAME"
    printf 'Content-Transfer-Encoding: base64\r\n'
    printf 'Content-Disposition: attachment; filename="%s"\r\n' "$ATTACH_NAME"
    printf '\r\n'
    openssl base64 < "$GZ"
    printf '\r\n'

    printf -- '--%s--\r\n' "$BOUNDARY"
} | sendmail -t -i

rc=$?
if [ "$rc" -ne 0 ]; then
    echo "ERROR: sendmail returned $rc" >&2
    exit "$rc"
fi

exit 0
