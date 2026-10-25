#!/bin/sh
#
# tarpit - Universal multi-protocol network tarpit
#
# PROVIDE: tarpit
# REQUIRE: NETWORKING syslogd pf
# KEYWORD: shutdown
#
# Installation:
#   cp tarpit.rc.d /usr/local/etc/rc.d/tarpit
#   chmod 555 /usr/local/etc/rc.d/tarpit
#
# /etc/rc.conf variables:
#   tarpit_enable   = "YES"           # mandatory to start
#   tarpit_user     = "tarpit"        # unprivileged user to run as
#   tarpit_group    = "tarpit"        # group
#   tarpit_config   = "/usr/local/etc/tarpit/tarpit.toml"
#   tarpit_flags    = ""              # extra flags to tarpit binary
#
# Usage:
#   service tarpit start
#   service tarpit stop
#   service tarpit status
#   service tarpit restart
#
# We use /usr/sbin/daemon(8) to handle backgrounding and PID-file tracking,
# and run the tarpit binary with --foreground so it does not attempt its own
# fork().  This is the idiomatic pattern for third-party rc.d services that
# self-manage as daemons; it avoids double-fork races and lets rc.d's normal
# stop/status machinery work against the correct PID.

. /etc/rc.subr

name="tarpit"
desc="Universal multi-protocol network tarpit"
rcvar="tarpit_enable"

load_rc_config "${name}"

# ---------------------------------------------------------------------------
# Defaults (overridden by /etc/rc.conf)
# ---------------------------------------------------------------------------
: "${tarpit_enable:=NO}"
: "${tarpit_user:=tarpit}"
: "${tarpit_group:=tarpit}"
: "${tarpit_config:=/usr/local/etc/tarpit/tarpit.toml}"
: "${tarpit_flags:=}"

# ---------------------------------------------------------------------------
# rc.subr integration
# ---------------------------------------------------------------------------
pidfile="/var/run/${name}.pid"
required_files="${tarpit_config}"

# The real binary; daemon(8) wraps it.
_command="/usr/local/bin/tarpit"
_command_args="--config ${tarpit_config} --foreground ${tarpit_flags}"

# Override start/stop/status to use daemon(8) for correct PID tracking.
start_cmd="${name}_start"
stop_cmd="${name}_stop"
status_cmd="${name}_status"

# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------

tarpit_prestart()
{
    # Verify config before starting so errors surface early.
    if ! "${_command}" --config "${tarpit_config}" --check > /dev/null 2>&1; then
        err 1 "Configuration check failed; run: ${_command} --check --config ${tarpit_config}"
    fi
}

tarpit_start()
{
    tarpit_prestart

    check_startmsgs && echo "Starting ${desc}."

    # daemon(8) flags:
    #   -f   redirect child stdout/stderr to /dev/null
    #   -p   write child PID to pidfile (used by stop/status)
    #   -u   drop to this user before exec
    /usr/sbin/daemon \
        -f \
        -p "${pidfile}" \
        -u "${tarpit_user}" \
        ${_command} ${_command_args}

    # Brief pause so a misconfigured binary fails fast and we can report it.
    sleep 0.3
    if ! tarpit_running; then
        warn "${name} failed to start (check syslog for details)"
        return 1
    fi
    echo "${desc} started, pid=$(cat "${pidfile}" 2>/dev/null)."
}

tarpit_stop()
{
    if ! tarpit_running; then
        echo "${name} is not running."
        return 0
    fi
    local pid
    pid=$(cat "${pidfile}" 2>/dev/null)
    echo "Stopping ${desc} (pid ${pid})."
    kill -TERM "${pid}" 2>/dev/null
    # Wait up to 10 s for clean exit.
    local i=0
    while [ "${i}" -lt 100 ] && tarpit_running; do
        sleep 0.1
        i=$((i + 1))
    done
    if tarpit_running; then
        warn "${name} did not stop cleanly; sending SIGKILL."
        kill -KILL "${pid}" 2>/dev/null
    fi
    rm -f "${pidfile}"
    echo "${desc} stopped."
}

tarpit_status()
{
    if tarpit_running; then
        echo "${name} is running as pid $(cat "${pidfile}" 2>/dev/null)."
    else
        echo "${name} is not running."
        return 1
    fi
}

tarpit_running()
{
    [ -f "${pidfile}" ] && kill -0 "$(cat "${pidfile}")" 2>/dev/null
}

run_rc_command "$1"
