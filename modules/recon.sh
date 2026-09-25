#!/usr/bin/env bash
# =============================================================================
# modules/recon.sh  —  Phase 4.1 Reconnaissance
# -----------------------------------------------------------------------------
#   - Host availability check (is the target up?)
#   - IP / hostname resolution (forward + reverse)
#   - Basic network information (RTT, hop distance estimate)
#
# Relies on helpers from utils.sh. Sets the global RECON_SUMMARY string and
# writes a human-readable recon block into the scan output file.
# =============================================================================
[[ -n "${__RECON_SH_LOADED:-}" ]] && return 0
__RECON_SH_LOADED=1

# Populated by recon_run for later phases / the report.
RESOLVED_IP=""
RESOLVED_HOST=""

# -----------------------------------------------------------------------------
# recon_is_alive TARGET
#   Return 0 if the host answers ICMP echo, 1 otherwise.
#   Some hosts drop ICMP but still expose services, so callers may choose to
#   continue anyway (see secscan.sh --force / nmap -Pn fallback).
# -----------------------------------------------------------------------------
recon_is_alive() {
    local target="$1"
    # -c 2 : two probes, -W 2 : 2s wait. Redirect noise; we only want the code.
    ping -c 2 -W 2 "$target" >/dev/null 2>&1
}

# -----------------------------------------------------------------------------
# recon_resolve TARGET
#   Fill RESOLVED_IP and RESOLVED_HOST. Works whether the target was given as
#   an IP or a hostname. Falls back gracefully when tools are missing.
# -----------------------------------------------------------------------------
recon_resolve() {
    local target="$1"

    # Is the target already a dotted-quad IPv4 address?
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        RESOLVED_IP="$target"
        # Try a reverse lookup for a friendly name (best-effort).
        if have_cmd dig; then
            # Filter dig's own error lines (";; communications error", "unreachable",
            # etc.) so a DNS-less lab network doesn't leak noise into the report.
            RESOLVED_HOST="$(dig +short -x "$target" 2>/dev/null \
                | grep -vE '^;|communications error|unreachable|timed out|no servers|connection' \
                | head -1 | sed 's/\.$//')"
        elif have_cmd host; then
            RESOLVED_HOST="$(host "$target" 2>/dev/null | awk '/pointer/{print $NF}' | head -1 | sed 's/\.$//')"
        fi
    else
        # Target is a hostname — resolve to an IP.
        RESOLVED_HOST="$target"
        if have_cmd dig; then
            RESOLVED_IP="$(dig +short "$target" A 2>/dev/null | grep -E '^[0-9]' | head -1)"
        elif have_cmd host; then
            RESOLVED_IP="$(host "$target" 2>/dev/null | awk '/has address/{print $NF}' | head -1)"
        elif have_cmd getent; then
            RESOLVED_IP="$(getent hosts "$target" 2>/dev/null | awk '{print $1}' | head -1)"
        fi
    fi
    [[ -z "$RESOLVED_HOST" ]] && RESOLVED_HOST="(no reverse DNS)"
    [[ -z "$RESOLVED_IP"   ]] && RESOLVED_IP="(unresolved)"
}

# -----------------------------------------------------------------------------
# recon_rtt TARGET  — echo an average round-trip time string, best effort.
# -----------------------------------------------------------------------------
recon_rtt() {
    local target="$1" out
    out="$(ping -c 3 -W 2 "$target" 2>/dev/null | tail -1)"
    # Typical last line: rtt min/avg/max/mdev = 0.123/0.145/0.170/0.019 ms
    if [[ "$out" == *=* ]]; then
        echo "${out#*= }"
    else
        echo "n/a"
    fi
}

# -----------------------------------------------------------------------------
# recon_run TARGET
#   Orchestrate the recon phase, print decisions, and append a clean block to
#   the scan output file ($SCAN_TXT). Returns 0 if the host looks reachable,
#   1 if it does not.
# -----------------------------------------------------------------------------
recon_run() {
    local target="$1"
    log_section "Reconnaissance — $target"

    recon_resolve "$target"
    log_info "Resolved IP   : $RESOLVED_IP"
    log_info "Hostname/PTR  : $RESOLVED_HOST"

    local alive="no" rtt="n/a"
    if recon_is_alive "$target"; then
        alive="yes"
        rtt="$(recon_rtt "$target")"
        log_detect "Host is up (ICMP echo reply received)"
        log_info   "Average RTT   : $rtt"
    else
        log_error "Host did not answer ICMP (may be filtered or down)"
    fi

    # Append a structured recon block to the raw scan file.
    {
        echo "======================================================================"
        echo " RECONNAISSANCE"
        echo "======================================================================"
        echo "Target        : $target"
        echo "Resolved IP   : $RESOLVED_IP"
        echo "Hostname/PTR  : $RESOLVED_HOST"
        echo "ICMP reachable: $alive"
        echo "Average RTT   : $rtt"
        echo
    } >> "$SCAN_TXT"

    [[ "$alive" == "yes" ]]
}
