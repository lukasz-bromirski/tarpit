#!/bin/sh
# install.sh - FreeBSD installation script for tarpit
# v1.1
#
# Run from the project root directory after building the binary:
#
#   cargo build --release
#   sudo sh install.sh
#
# Options:
#   --yes        accept all prompts automatically (for scripted installs)
#   --uninstall  remove tarpit from the system
#   --clean      stop the running service, wipe /usr/local/etc/tarpit/
#                (config + cert + key), then proceed with a fresh install
#                of all files.  Useful for rolling out config-schema
#                changes between versions where you do NOT want the
#                normal install-time "preserve existing config" behaviour.
#
# The script is idempotent: running it a second time is safe and will
# skip steps that are already complete.  --clean is the escape hatch
# from that idempotency for the config directory specifically.

set -u   # treat unset variables as errors

# ---------------------------------------------------------------------------
# Configurable paths (edit here if your layout differs)
# ---------------------------------------------------------------------------

PROG="tarpit"
TARPIT_USER="tarpit"
TARPIT_GROUP="tarpit"

BIN_SRC="target/release/${PROG}"
BIN_DEST="/usr/local/bin/${PROG}"

RCD_SRC="tarpit.rc.d"
RCD_DEST="/usr/local/etc/rc.d/${PROG}"

REPORT_SRC="tarpit-report.sh"
REPORT_DST="/usr/local/bin/tarpit-report.sh"

resolve_invoking_user() {
    if   [ -n "${SUDO_USER:-}" ]; then echo "$SUDO_USER"
    elif [ -n "${DOAS_USER:-}" ]; then echo "$DOAS_USER"
    else logname 2>/dev/null || echo root
    fi
}

INVOKING_USER=$(resolve_invoking_user)
INVOKING_HOME=$(eval echo "~$INVOKING_USER")

MAIL_REPORT_SRC="tarpit-mail-report.sh"
MAIL_REPORT_DST="${INVOKING_HOME}/tarpit-mail-report.sh"

CONF_DIR="/usr/local/etc/${PROG}"
CONF_SRC="tarpit.toml"
CONF_DEST="${CONF_DIR}/tarpit.toml"
CERT_DEST="${CONF_DIR}/cert.pem"
KEY_DEST="${CONF_DIR}/key.pem"

LOG_FILE="/var/log/tarpit.log"
NEWSYSLOG_CONF="/etc/newsyslog.conf"
SYSLOG_CONF="/etc/syslog.conf"

# Marker used to detect whether our syslog.conf block is already present.
SYSLOG_MARKER="!${PROG}"

# Values computed at install time and substituted into the installed config
# to make the tarpit masquerade as a legitimate server on this host.
# Populated by generate_masquerade_values() before step_config / step_tls.
MASQUERADE_HOSTNAME=""
MASQUERADE_APACHE=""
MASQUERADE_HTTP_DATE=""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

YES=0
UNINSTALL=0
CLEAN=0

for arg in "$@"; do
    case "${arg}" in
        --yes)       YES=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --clean)     CLEAN=1 ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown option: ${arg}" >&2
            echo "Usage: $0 [--yes] [--uninstall] [--clean]" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Apache version generator (for HTTP/HTTPS Server: header)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

# Width for the status column
W=60

info()  { printf "  %-${W}s" "$1"; }
pass()  { echo "[ OK ]"; }
skip()  { echo "[SKIP]"; }
done_() { echo "[DONE]"; }
warn()  { echo "[WARN] $1"; }

die() {
    echo ""
    echo "ERROR: $1" >&2
    exit 1
}

confirm() {
    # Returns 0 (yes) or 1 (no).  Defaults to No when non-interactive.
    local prompt="$1"
    if [ "${YES}" -eq 1 ]; then
        echo "  --> ${prompt} [auto: yes]"
        return 0
    fi
    printf "  %s [y/N] " "${prompt}"
    read -r _ans
    case "${_ans}" in
        [Yy]*) return 0 ;;
        *)     return 1 ;;
    esac
}

separator() {
    echo ""
    echo "--- $1 ---"
}

# ---------------------------------------------------------------------------
# Masquerade value generation
# ---------------------------------------------------------------------------

# Generate a plausible Apache version number, randomly picked from one of two
# valid major release ranges:
#   - 1.0.0 through 1.3.37 (the entire Apache 1.x line)
#   - 2.0.0 through 2.4.67 (Apache 2.x; in reality only minors 0, 2, 4 ever
#     shipped, so we pick from those to avoid impossible versions like 2.1.x)
#
# Uses jot(1) which is part of FreeBSD base - no extra packages needed.
random_apache_version() {
    if [ "$(jot -r 1 0 1)" -eq 0 ]; then
        # Apache 1.x branch: 1.0.0 - 1.3.37
        _minor=$(jot -r 1 0 3)
        _patch=$(jot -r 1 0 37)
        printf "1.%d.%d" "${_minor}" "${_patch}"
    else
        # Apache 2.x branch: only 2.0, 2.2 and 2.4 ever existed.
        # Patch ceilings reflect each branch's real last release.
        case "$(jot -r 1 0 2)" in
            0) _minor=0; _patch=$(jot -r 1 0 65) ;;   # 2.0.0 - 2.0.65
            1) _minor=2; _patch=$(jot -r 1 0 34) ;;   # 2.2.0 - 2.2.34
            *) _minor=4; _patch=$(jot -r 1 0 67) ;;   # 2.4.0 - 2.4.67
        esac
        printf "2.%d.%d" "${_minor}" "${_patch}"
    fi
}

# Capture the system hostname, randomise the Apache version, and snapshot the
# current UTC time in RFC 7231 / HTTP-date format.  These are used by sed
# substitutions in step_config and by openssl -subj in step_tls.
generate_masquerade_values() {
    MASQUERADE_HOSTNAME=$(hostname)
    MASQUERADE_APACHE=$(random_apache_version)
    MASQUERADE_HTTP_DATE=$(date -u +'%a, %d %b %Y %H:%M:%S GMT')

    info "Masquerade hostname:   ${MASQUERADE_HOSTNAME}"
    pass
    info "Masquerade Apache ver: ${MASQUERADE_APACHE}"
    pass
    info "Masquerade HTTP date:  ${MASQUERADE_HTTP_DATE}"
    pass
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

do_uninstall() {
    separator "Uninstalling ${PROG}"

    if ! confirm "This will stop and remove tarpit.  Continue?"; then
        echo "  Aborted."
        exit 0
    fi

    info "Stopping service"
    if service "${PROG}" status > /dev/null 2>&1; then
        service "${PROG}" stop > /dev/null 2>&1 && pass || warn "could not stop service"
    else
        skip
    fi

    info "Removing rc.conf entries"
    sysrc -x tarpit_enable  > /dev/null 2>&1 || true
    sysrc -x tarpit_user    > /dev/null 2>&1 || true
    sysrc -x tarpit_config  > /dev/null 2>&1 || true
    pass

    info "Removing rc.d script ${RCD_DEST}"
    rm -f "${RCD_DEST}" && pass || warn "could not remove ${RCD_DEST}"

    info "Removing binary ${BIN_DEST}"
    rm -f "${BIN_DEST}" && pass || warn "could not remove ${BIN_DEST}"

    echo ""
    echo "  Config, TLS keys, and log file were NOT removed."
    echo "  Remove manually if desired:"
    echo "    rm -rf ${CONF_DIR}"
    echo "    rm -f  ${LOG_FILE}"
    echo ""
    echo "  To remove the syslog.conf entry, delete the lines between"
    echo "  '${SYSLOG_MARKER}' and '!*' in ${SYSLOG_CONF}, then:"
    echo "    service syslogd reload"
    echo ""
    exit 0
}

# ---------------------------------------------------------------------------
# Clean: stop service + wipe config directory, then fall through to install.
# ---------------------------------------------------------------------------
# Used when you want a fresh-config install on top of an existing deployment
# (e.g. rolling out a new tarpit.toml schema between versions).  Unlike
# --uninstall, this:
#   - leaves the binary, rc.d script, and rc.conf entries in place
#     (they'll be overwritten / re-asserted by the install steps below)
#   - leaves /var/log/tarpit.log alone (logs are history; rotation handles
#     them via newsyslog)
#   - leaves the syslog.conf block in place (still valid for the new install)
#   - WIPES /usr/local/etc/tarpit/ entirely, so step_config writes a fresh
#     tarpit.toml and step_tls generates a fresh cert/key
#
# After do_clean returns, main() continues with the normal install flow.

do_clean() {
    separator "Clean install: wipe ${CONF_DIR} before reinstalling"

    if ! confirm "This will STOP tarpit and DELETE ${CONF_DIR}/* (config, cert, key).  Continue?"; then
        echo "  Aborted."
        exit 0
    fi

    info "Stopping service"
    if service "${PROG}" status > /dev/null 2>&1; then
        service "${PROG}" stop > /dev/null 2>&1 && pass || warn "could not stop service"
    else
        skip
    fi

    info "Wiping ${CONF_DIR}"
    if [ -d "${CONF_DIR}" ]; then
        # Guard: refuse to rm -rf anything other than the expected path.
        # Cheap defence against a typo'd CONF_DIR variable taking out /etc
        # or similar.  We REQUIRE the path to end in /tarpit.
        case "${CONF_DIR}" in
            */tarpit) ;;
            *)
                echo ""
                die "refusing to wipe '${CONF_DIR}' — does not end in '/tarpit'"
                ;;
        esac
        rm -rf "${CONF_DIR:?}"/* "${CONF_DIR:?}"/.[!.]* 2>/dev/null
        pass
    else
        skip
    fi

    echo ""
    echo "  Clean done.  Continuing with fresh install..."
    echo ""
    # Fall through — main() carries on with preflight + install steps.
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

preflight() {
    separator "Pre-flight checks"

    info "Running as root"
    if [ "$(id -u)" -ne 0 ]; then
        echo ""
        die "This script must be run as root.  Try: sudo sh $0"
    fi
    pass

    info "FreeBSD OS"
    if [ "$(uname -s)" != "FreeBSD" ]; then
        echo ""
        die "This script targets FreeBSD.  Detected: $(uname -s)"
    fi
    pass

    info "Binary built: ${BIN_SRC}"
    if [ ! -f "${BIN_SRC}" ]; then
        echo ""
        echo "  Binary not found.  Build it first:"
        echo "    cargo build --release"
        die "Binary missing: ${BIN_SRC}"
    fi
    pass

    info "rc.d script present: ${RCD_SRC}"
    if [ ! -f "${RCD_SRC}" ]; then
        echo ""
        die "rc.d script not found: ${RCD_SRC} (run from project root)"
    fi
    pass

    info "Config template present: ${CONF_SRC}"
    if [ ! -f "${CONF_SRC}" ]; then
        echo ""
        die "Config template not found: ${CONF_SRC} (run from project root)"
    fi
    pass

    info "openssl available"
    if ! command -v openssl > /dev/null 2>&1; then
        echo ""
        die "openssl not found.  Install with: pkg install openssl"
    fi
    pass
}

# ---------------------------------------------------------------------------
# Step functions
# ---------------------------------------------------------------------------

step_group() {
    separator "System user and group"

    info "Group '${TARPIT_GROUP}'"
    if pw groupshow "${TARPIT_GROUP}" > /dev/null 2>&1; then
        skip
    else
        pw groupadd "${TARPIT_GROUP}" \
            || die "Failed to create group '${TARPIT_GROUP}'"
        pass
    fi

    info "User '${TARPIT_USER}'"
    if pw usershow "${TARPIT_USER}" > /dev/null 2>&1; then
        skip
    else
        pw useradd "${TARPIT_USER}" \
            -g "${TARPIT_GROUP}" \
            -d /nonexistent \
            -s /usr/sbin/nologin \
            -c "Network tarpit daemon" \
            || die "Failed to create user '${TARPIT_USER}'"
        pass
    fi
}

step_binary() {
    separator "Binary"

    info "Installing ${BIN_DEST}"
    install -o root -g wheel -m 555 "${BIN_SRC}" "${BIN_DEST}" \
        || die "Failed to install binary"
    pass

    info "Binary version"
    _ver=$("${BIN_DEST}" --version 2>&1) && echo "[ ${_ver} ]" || warn "could not get version"
}

step_report() {
    separator "Report"

    info "Installing ${REPORT_DST}"
    install -o root -g wheel -m 555 "${REPORT_SRC}" "${REPORT_DST}" \
	|| die "Failed to install report"
    pass
}

step_mail_report() {
    separator "Mail report"

    info "Installing ${MAIL_REPORT_SRC}"
    install -o root -g wheel -m 555 "${MAIL_REPORT_SRC}" "${MAIL_REPORT_DST}" \
	|| die "Failed to install mail report"
    pass
}

step_config() {
    separator "Configuration"

    info "Config directory ${CONF_DIR}"
    if [ -d "${CONF_DIR}" ]; then
        skip
    else
        install -d -o root -g "${TARPIT_GROUP}" -m 750 "${CONF_DIR}" \
            || die "Failed to create ${CONF_DIR}"
        pass
    fi

    info "Config file ${CONF_DEST}"
    if [ -f "${CONF_DEST}" ]; then
        # Never overwrite an existing config - the user may have customised it.
        # To refresh masquerade values, delete the file and re-run install.sh.
        skip
        echo "  --> Existing config preserved.  Review ${CONF_SRC} for new options."
    else
        # Three live substitutions from CONF_SRC → CONF_DEST:
        #   1. mail.example.com         → actual hostname            (SMTP/SMTPS greeting)
        #   2. Apache/2.4.62 (FreeBSD)  → Apache/<ver> + hostname    (HTTP/HTTPS Server: line)
        #   3. Thu, 01 Jan 2099 ...     → current UTC HTTP-date      (HTTP/HTTPS Date: line)
        #
        # Substitution #2 uses the same suffix Apache emits in its ServerSignature
        # footer (e.g. on default 404 pages): "Server at <host> Port <n>".  That
        # mirrors a real Apache box on the wire.
        #
        # Sed delimiter '|' is safe: hostnames, version numbers and HTTP dates
        # never contain '|'.  Backslashes in the patterns escape literal dots.
        _tmp=$(mktemp -t tarpit-toml) || die "mktemp failed"
        sed \
            -e "s|mail\\.example\\.com|${MASQUERADE_HOSTNAME}|g" \
            -e "s|Apache/2\\.4\\.62 (FreeBSD)|Apache/${MASQUERADE_APACHE} (FreeBSD) Server at ${MASQUERADE_HOSTNAME} Port 80|g" \
            -e "s|Thu, 01 Jan 2099 00:00:00 GMT|${MASQUERADE_HTTP_DATE}|g" \
            "${CONF_SRC}" > "${_tmp}" \
            || { rm -f "${_tmp}"; die "sed substitution failed"; }
        install -o root -g wheel -m 644 "${_tmp}" "${CONF_DEST}" \
            || { rm -f "${_tmp}"; die "Failed to install config"; }
        rm -f "${_tmp}"
        pass
        echo "  --> HTTP Server header:  Apache/${MASQUERADE_APACHE} (FreeBSD) Server at ${MASQUERADE_HOSTNAME} Port 80"
        echo "  --> HTTP Date header:    ${MASQUERADE_HTTP_DATE}"
        echo "  --> SMTP greeting host:  ${MASQUERADE_HOSTNAME}"
        echo "  --> Edit ${CONF_DEST} before starting the service if needed."
    fi
}

step_tls() {
    separator "TLS certificate (self-signed)"

    info "Certificate ${CERT_DEST}"
    if [ -f "${CERT_DEST}" ] && [ -f "${KEY_DEST}" ]; then
        skip
        echo "  --> Existing cert/key preserved."
        return
    fi
    pass   # will generate below

    info "Generating EC P-256 certificate (CN=${MASQUERADE_HOSTNAME})"
    openssl req \
        -x509 \
        -newkey ec \
        -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "${KEY_DEST}" \
        -out    "${CERT_DEST}" \
        -days   3650 \
        -nodes \
        -subj   "/CN=${MASQUERADE_HOSTNAME}" \
        2>/dev/null \
        || die "openssl failed to generate certificate"
    pass

    info "Setting key permissions (root:${TARPIT_GROUP} 640)"
    chmod 640             "${KEY_DEST}"  || die "chmod key"
    chown "root:${TARPIT_GROUP}" "${KEY_DEST}"  || die "chown key"
    chmod 644             "${CERT_DEST}" || die "chmod cert"
    pass

    echo "  --> Self-signed cert valid for 3650 days."
    echo "  --> Replace with a real cert from Let's Encrypt for better fingerprinting."
}

step_rcd() {
    separator "rc.d service script"

    info "Installing ${RCD_DEST}"
    install -o root -g wheel -m 555 "${RCD_SRC}" "${RCD_DEST}" \
        || die "Failed to install rc.d script"
    pass

    info "Enabling in /etc/rc.conf via sysrc"
    sysrc "tarpit_enable=YES"                       > /dev/null || die "sysrc tarpit_enable"
    sysrc "tarpit_user=${TARPIT_USER}"              > /dev/null || die "sysrc tarpit_user"
    sysrc "tarpit_config=${CONF_DEST}"              > /dev/null || die "sysrc tarpit_config"
    pass
}

step_syslog() {
    separator "syslog configuration"

    info "syslog.conf entry for '${PROG}'"
    if grep -q "^${SYSLOG_MARKER}$" "${SYSLOG_CONF}" 2>/dev/null; then
        skip
    else
        # Append the program-specific block.
        # !tarpit     - only lines from the tarpit process
        # *.*         - all facilities and severities
        # !*          - reset to "all programs" for subsequent rules
        cat >> "${SYSLOG_CONF}" << EOF

# ${PROG} - network tarpit (added by install.sh $(date +%Y-%m-%d))
${SYSLOG_MARKER}
*.*							${LOG_FILE}
!*
EOF
        pass
    fi

    info "Log file ${LOG_FILE}"
    if [ ! -f "${LOG_FILE}" ]; then
        touch "${LOG_FILE}"                       || die "touch ${LOG_FILE}"
        chmod 644 "${LOG_FILE}"                   || die "chmod log"
        chown "root:${TARPIT_GROUP}" "${LOG_FILE}" || die "chown log"
        pass
    else
        skip
    fi

    info "newsyslog.conf entry for ${LOG_FILE}"
    if grep -q "${LOG_FILE}" "${NEWSYSLOG_CONF}" 2>/dev/null; then
        skip
    else
        # Columns: path  mode  count  size  when  flags
        #   mode  640  = rw-r-----
        #   count 14   = keep 14 rotated archives
        #   size  *    = no size limit (rotate by time only)
        #   @T00  = rotate daily at midnight
        #   J     = bzip2 compress rotated files
        #   C     = create log file if it doesn't exist
        printf "%-40s 644  14    *    @T00   JC\n" \
            "${LOG_FILE}" >> "${NEWSYSLOG_CONF}" \
            || die "Failed to update newsyslog.conf"
        pass
    fi

    info "Reloading syslogd"
    service syslogd reload > /dev/null 2>&1 \
        || die "Failed to reload syslogd"
    pass
}

step_start() {
    separator "Service startup"

    echo "  Installation complete.  Next steps:"
    echo ""
    echo "  1. Review and customise the config:"
    echo "       ${CONF_DEST}"
    echo ""
    echo "  2. Configure pf(4) port redirects (see pf.conf.example)."
    echo "     IMPORTANT: add your management IPs to <tarpit_bypass> first"
    echo "     or you will redirect your own SSH session into the tarpit."
    echo ""
    echo "  3. Load the pf rules:"
    echo "       pfctl -n -f /etc/pf.conf   # syntax check"
    echo "       pfctl -f /etc/pf.conf"
    echo ""

    if confirm "Start tarpit now?"; then
        info "Starting ${PROG}"
        if service "${PROG}" start > /dev/null 2>&1; then
            pass
            echo ""
            echo "  Check status:   service ${PROG} status"
            echo "  Watch log:      tail -f ${LOG_FILE}"
	    echo "  Check sockets:  sockstat -46l | grep ${PROG}"
        else
            echo ""
            warn "service start failed - check the log:"
            warn "  tail -f ${LOG_FILE}"
            warn "  ${BIN_DEST} --foreground --config ${CONF_DEST}"
        fi
    else
        echo "  Start manually when ready:"
        echo "    service ${PROG} start"
    fi

    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    echo ""
    echo "==========================================="
    echo "  tarpit - FreeBSD installer"
    echo "==========================================="

    if [ "${UNINSTALL}" -eq 1 ]; then
        do_uninstall
    fi

    # --clean stops the service and wipes ${CONF_DIR} before the normal
    # install flow runs.  Falls through (does NOT exit) so the install
    # steps below take effect on the now-empty config directory.
    if [ "${CLEAN}" -eq 1 ]; then
        do_clean
    fi

    preflight
    separator "Generating masquerade values for this install"
    generate_masquerade_values
    step_group
    step_binary
    step_report 
    step_mail_report
    step_config
    step_tls
    step_rcd
    step_syslog
    step_start
}

main "$@"
