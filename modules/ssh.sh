#!/usr/bin/env bash
# =============================================================================
# modules/ssh.sh  —  SSH service checks
#   Check: grab the SSH version/banner and reason about it.
#   Evidence: the exact protocol banner the server presents on connect.
# =============================================================================
[[ -n "${__SSH_SH_LOADED:-}" ]] && return 0
__SSH_SH_LOADED=1

# ssh_check PORT TARGET
ssh_check() {
    local port="$1" target="$2"
    log_detect "SSH detected on port $port"
    log_action "Starting SSH enumeration..."

    # SSH servers send their identification string immediately on connect,
    # e.g.  SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
    local banner
    banner="$(grab_banner "$target" "$port")"

    if [[ -z "$banner" ]]; then
        # Fall back to whatever nmap's version detection reported.
        banner="${VERSION_BY_PORT[$port]}"
    fi

    if [[ -z "$banner" ]]; then
        log_info "Could not read an SSH banner."
        record_finding "INFO" "SSH" "SSH banner not readable" \
            "No identification string was returned from ${target}:${port} within the timeout." \
            "Not conclusive on its own; the service may be filtered or slow." \
            "Re-run manually: nc ${target} ${port}  (the banner appears on connect)."
        return 0
    fi

    log_info "SSH banner: $banner"

    # Protocol version note: SSH-1.x is cryptographically broken.
    if [[ "$banner" == SSH-1.* ]]; then
        record_finding "HIGH" "SSH" "Legacy SSH protocol v1 offered" \
            "Banner: ${banner} — the server advertises SSH protocol version 1." \
            "SSHv1 has fundamental cryptographic weaknesses and is trivially attackable." \
            "Disable protocol 1 entirely; allow only 'Protocol 2' (default on modern OpenSSH)."
    fi

    # Heuristic on OpenSSH version — evidence-based, not a definitive CVE claim.
    # We surface the exact version so the reviewer can confirm against CVE data.
    if [[ "$banner" =~ OpenSSH[_/]([0-9]+)\.([0-9]+) ]]; then
        local major="${BASH_REMATCH[1]}" minor="${BASH_REMATCH[2]}"
        local sev="INFO" note="Current-looking OpenSSH version."
        # OpenSSH < 7.x is old enough that outdated-software risk is worth flagging.
        if (( major < 7 )); then
            sev="MEDIUM"
            note="OpenSSH ${major}.${minor} is significantly outdated and likely affected by multiple public CVEs (e.g. user-enumeration / DoS classes)."
        fi
        record_finding "$sev" "SSH" "OpenSSH version identified: ${major}.${minor}" \
"Banner: ${banner}
Parsed version: OpenSSH ${major}.${minor}" \
            "$note" \
            "Compare the exact version against the OpenSSH release notes / CVE database and patch to the current stable release."
    else
        record_finding "INFO" "SSH" "SSH server identified" \
            "Banner: ${banner}" \
            "The software/version is exposed to unauthenticated clients." \
            "Keep the SSH server patched; consider key-only auth and fail2ban."
    fi
    return 0
}
