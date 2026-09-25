#!/usr/bin/env bash
# =============================================================================
# modules/portscan.sh  —  Phase 4.2 Port & Service Enumeration
# -----------------------------------------------------------------------------
# Runs nmap once (TCP connect + service/version detection), stores the raw
# output in the report, then PARSES the greppable output into structured Bash
# data so later phases can make decisions per service.
#
# This is deliberately NOT "a one-liner around nmap": the value here is the
# parsing + the structured data model the rest of the tool branches on.
#
# Exposes:
#   OPEN_PORTS[]          -> array of open TCP port numbers
#   SERVICE_BY_PORT[port] -> service name reported by nmap (e.g. ftp, http)
#   VERSION_BY_PORT[port] -> version banner reported by nmap (may be empty)
# =============================================================================
[[ -n "${__PORTSCAN_SH_LOADED:-}" ]] && return 0
__PORTSCAN_SH_LOADED=1

# -g (global): this file is sourced inside load_modules(); without -g these
# would be function-local and disappear before the scan uses them.
declare -ga OPEN_PORTS=()
declare -gA SERVICE_BY_PORT=()
declare -gA VERSION_BY_PORT=()

# Extra nmap flags the main script may set (e.g. "-p-" for a full scan).
: "${NMAP_PORT_ARGS:=}"

# -----------------------------------------------------------------------------
# portscan_parse_grep GREPFILE
#   Parse an nmap greppable (-oG) file and populate the global port arrays.
#   Greppable port tokens look like:  21/open/tcp//ftp//vsftpd 2.3.4/
#   Fields (split on '/'):  1=port 2=state 3=proto 4=owner 5=service 7=version
# -----------------------------------------------------------------------------
portscan_parse_grep() {
    local grepfile="$1"
    local ports_field token port state proto service version

    # Pull the text after "Ports: " up to the next tab, for every Host line.
    ports_field="$(grep -h '^Host:.*Ports:' "$grepfile" 2>/dev/null \
                   | sed -e 's/.*Ports: //' -e 's/\tIgnored.*//' -e 's/\t.*//')"
    [[ -z "$ports_field" ]] && return 0

    # Tokens are comma+space separated. Split safely with an array.
    local IFS=','
    read -ra tokens <<< "$ports_field"
    unset IFS

    for token in "${tokens[@]}"; do
        token="${token#"${token%%[![:space:]]*}"}"   # ltrim
        # Split this token on '/'.
        IFS='/' read -r port state proto _owner service _rpc version _rest <<< "$token"
        [[ "$state" == "open" && "$proto" == "tcp" ]] || continue
        [[ "$port" =~ ^[0-9]+$ ]] || continue

        OPEN_PORTS+=( "$port" )
        SERVICE_BY_PORT["$port"]="${service:-unknown}"
        # Version may legitimately be empty; trim a trailing slash if present.
        VERSION_BY_PORT["$port"]="${version%/}"
    done
}

# -----------------------------------------------------------------------------
# portscan_print_table
#   Pretty structured table -> console and scan file. This is the "structured
#   format (not raw scattered output)" the brief asks for.
# -----------------------------------------------------------------------------
portscan_print_table() {
    local port line
    {
        echo "======================================================================"
        echo " OPEN PORTS & SERVICES"
        echo "======================================================================"
        printf '%-10s %-8s %-14s %s\n' "PORT" "STATE" "SERVICE" "VERSION"
        printf '%-10s %-8s %-14s %s\n' "----" "-----" "-------" "-------"
    } | tee -a "$SCAN_TXT"

    for port in "${OPEN_PORTS[@]}"; do
        line="$(printf '%-10s %-8s %-14s %s' \
                "${port}/tcp" "open" \
                "${SERVICE_BY_PORT[$port]}" "${VERSION_BY_PORT[$port]:-—}")"
        printf '%s\n' "$line" | tee -a "$SCAN_TXT"
    done
    echo | tee -a "$SCAN_TXT"
}

# -----------------------------------------------------------------------------
# portscan_run TARGET
#   Execute the scan and populate structured data. Returns:
#     0  -> at least one open port found
#     1  -> nmap missing (fatal, caller decides)
#     2  -> nmap ran but no open TCP ports were found
# -----------------------------------------------------------------------------
portscan_run() {
    local target="$1"
    log_section "Port & Service Enumeration — $target"

    # nmap is the ONE hard dependency for this phase.
    if ! need_cmd nmap; then
        return 1
    fi

    local grepfile="${OUT_DIR}/nmap.grep"
    local normfile="${OUT_DIR}/nmap.normal"

    # -Pn : we already did our own reachability check; many lab VMs filter ICMP
    #        but still expose services, so don't let host-discovery skip them.
    # -sV : service/version detection (core requirement).
    # -T4 : reasonable speed for an isolated lab network.
    # --version-intensity 5 keeps version detection thorough but a bit faster on
    # service-heavy hosts (e.g. Metasploitable) than the default intensity 7.
    log_action "Running: nmap -sV -Pn -T4 ${NMAP_PORT_ARGS} $target"
    log_info   "(service-heavy hosts can take a few minutes; live timer below)"

    # Run nmap in the background and show a live elapsed-time spinner, so a long
    # version scan never looks like the tool has frozen.
    nmap -sV -Pn -T4 --version-intensity 5 ${NMAP_PORT_ARGS} \
         -oG "$grepfile" -oN "$normfile" "$target" >/dev/null 2>>"$LOG_FILE" &
    local npid=$! spin='|/-\' k=0 secs=0
    if [[ -t 1 ]]; then   # only animate on a real terminal
        while kill -0 "$npid" 2>/dev/null; do
            printf '\r%s[*]%s scanning... %3ss %s' "$C_CYAN" "$C_RESET" "$secs" "${spin:k++%4:1}"
            sleep 1; secs=$((secs+1))
        done
        printf '\r%*s\r' 48 ''   # clear the spinner line
    fi
    wait "$npid"
    if [[ $? -ne 0 ]]; then
        log_error "nmap exited with an error (see log). Continuing with any partial output."
    fi

    # Fold the human-readable nmap output into the scan file for the record.
    if [[ -f "$normfile" ]]; then
        {
            echo "----------------------------------------------------------------------"
            echo " RAW NMAP OUTPUT (nmap -sV -Pn -T4 ${NMAP_PORT_ARGS})"
            echo "----------------------------------------------------------------------"
            cat "$normfile"
            echo
        } >> "$SCAN_TXT"
    fi

    # Parse into structured data.
    [[ -f "$grepfile" ]] && portscan_parse_grep "$grepfile"

    if [[ ${#OPEN_PORTS[@]} -eq 0 ]]; then
        log_info "No open TCP ports were found."
        record_finding "INFO" "GENERAL" "No open TCP ports detected" \
            "nmap -sV -Pn against $target returned no open TCP ports." \
            "Nothing exposed over TCP is a good posture, but confirm the target/network is correct." \
            "Re-check the VM IP and that host-only networking is up if you expected services."
        return 2
    fi

    log_detect "Found ${#OPEN_PORTS[@]} open TCP port(s): ${OPEN_PORTS[*]}"
    portscan_print_table
    return 0
}
