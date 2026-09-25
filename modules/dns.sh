#!/usr/bin/env bash
# =============================================================================
# modules/dns.sh  —  DNS service checks
#   Checks:
#     1) Zone transfer (AXFR) against candidate zones — the classic DNS misconfig.
#     2) version.bind disclosure.
#   A successful AXFR dumps an organisation's entire internal DNS map, so it is
#   a high-value finding. Requires `dig`.
# =============================================================================
[[ -n "${__DNS_SH_LOADED:-}" ]] && return 0
__DNS_SH_LOADED=1

# Optional zone the operator can hint via the environment (secscan.sh --zone).
: "${DNS_ZONE:=}"

# dns_candidate_zones  — echo a de-duplicated list of zone names worth trying.
dns_candidate_zones() {
    local -a cands=()
    [[ -n "$DNS_ZONE" ]] && cands+=( "$DNS_ZONE" )

    # Use the reverse-resolved hostname and its parent domain if we have one.
    if [[ -n "$RESOLVED_HOST" && "$RESOLVED_HOST" != "(no reverse DNS)" ]]; then
        cands+=( "$RESOLVED_HOST" )
        if [[ "$RESOLVED_HOST" == *.*.* ]]; then
            cands+=( "${RESOLVED_HOST#*.}" )   # strip the first label
        fi
    fi

    # De-duplicate while preserving order.
    printf '%s\n' "${cands[@]}" | awk 'NF && !seen[$0]++'
}

# dns_check PORT TARGET
dns_check() {
    local port="$1" target="$2"
    log_detect "DNS detected on port $port"
    log_action "Starting DNS enumeration..."

    if ! have_cmd dig; then
        log_info "dig not installed — skipping DNS checks."
        record_finding "INFO" "DNS" "DNS checks skipped (dig missing)" \
            "DNS is open on ${target}:${port} but 'dig' is not installed on the scanning host." \
            "Informational — reflects the scanner, not the target." \
            "Install dnsutils (dig) to enable zone-transfer testing."
        return 0
    fi

    # --- version.bind --------------------------------------------------------
    local ver
    ver="$(run_capture 10 dig +short @"$target" version.bind txt chaos 2>/dev/null | tr -d '"')"
    if [[ -n "$ver" ]]; then
        log_info "version.bind: $ver"
        record_finding "LOW" "DNS" "DNS server version disclosed (version.bind)" \
            "dig @${target} version.bind txt chaos -> ${ver}" \
            "Exposing the resolver version helps attackers match known CVEs." \
            "Hide the version (BIND: 'version \"not disclosed\";' in options)."
    fi

    # --- Zone transfer -------------------------------------------------------
    local -a zones
    mapfile -t zones < <(dns_candidate_zones)

    if [[ ${#zones[@]} -eq 0 ]]; then
        log_info "No candidate zone name known — cannot attempt AXFR automatically."
        record_finding "INFO" "DNS" "Zone transfer not attempted (no zone name)" \
            "DNS is open on ${target}:${port} but no zone name could be derived (no reverse DNS). AXFR needs a zone name." \
            "Not a weakness by itself." \
            "Re-run with a known zone: ./secscan.sh --zone example.local ${target}"
        return 0
    fi

    local zone out transferred="no"
    for zone in "${zones[@]}"; do
        log_action "Attempting AXFR for zone '${zone}'..."
        out="$(run_capture 20 dig AXFR @"$target" "$zone" 2>/dev/null)"
        # Success = multiple records and no explicit failure message.
        if grep -qiE 'Transfer failed|connection timed out|communications error' <<< "$out"; then
            continue
        fi
        # Count real record lines (skip comments/blank).
        local recs
        recs="$(grep -cvE '^\s*;|^\s*$' <<< "$out")"
        if [[ "$recs" -gt 1 ]]; then
            transferred="yes"
            record_finding "HIGH" "DNS" "DNS zone transfer (AXFR) allowed" \
"Command: dig AXFR @${target} ${zone}
Records returned: ${recs}. Sample:
$(grep -vE '^\s*;|^\s*$' <<< "$out" | head -12)" \
                "AXFR to any client leaks every host in the zone — a complete internal network map for an attacker." \
                "Restrict zone transfers to authorised secondaries only (BIND: allow-transfer { <secondary IPs>; };)."
            break
        fi
    done

    if [[ "$transferred" == "no" ]]; then
        log_info "Zone transfer refused for all tried zones."
        record_finding "INFO" "DNS" "Zone transfer refused" \
            "AXFR was attempted for: ${zones[*]}. All attempts were refused or returned no zone data." \
            "Refusing AXFR to arbitrary clients is the correct behaviour." \
            "Keep allow-transfer restricted to known secondaries."
    fi
    return 0
}
