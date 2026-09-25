#!/usr/bin/env bash
# =============================================================================
# modules/smb.sh  —  SMB / NetBIOS service checks
#   Check: enumerate shares over a NULL session (unauthenticated).
#   Tools: smbclient if present, otherwise fall back to nmap's smb-enum-shares
#          NSE script. Demonstrates graceful degradation between tools.
# =============================================================================
[[ -n "${__SMB_SH_LOADED:-}" ]] && return 0
__SMB_SH_LOADED=1

# smb_check PORT TARGET
smb_check() {
    local port="$1" target="$2"
    log_detect "SMB detected on port $port"
    log_action "Starting SMB enumeration..."

    # ---- Preferred path: smbclient null-session share listing ---------------
    if have_cmd smbclient; then
        local out rc
        out="$(run_capture 25 smbclient -L "//${target}" -N 2>&1)"
        rc=$?
        # A share list contains a "Sharename" header when the null session works.
        if grep -qi 'Sharename' <<< "$out"; then
            local shares
            shares="$(awk '/Sharename/{f=1} f' <<< "$out" | head -15)"
            record_finding "HIGH" "SMB" "SMB shares listed via NULL session" \
"Command: smbclient -L //${target} -N   (no credentials)
Shares returned:
${shares}" \
                "Unauthenticated share enumeration reveals the attack surface and may expose readable/writable shares containing sensitive data." \
                "Disable NULL/guest sessions (restrict anonymous), require authentication, and remove unnecessary shares."
        else
            log_info "smbclient NULL session did not return a share list."
            record_finding "INFO" "SMB" "SMB present; NULL-session listing refused" \
                "smbclient -L //${target} -N returned no share list (exit ${rc}); anonymous enumeration appears restricted." \
                "Refusing anonymous enumeration is the correct behaviour." \
                "Confirm guest access is disabled and keep SMB patched (no SMBv1)."
        fi
        return 0
    fi

    # ---- Fallback path: nmap NSE --------------------------------------------
    if have_cmd nmap; then
        log_info "smbclient not installed — falling back to nmap NSE (smb-enum-shares / smb-os-discovery)."
        local nse
        nse="$(run_capture 60 nmap -p "$port" --script smb-os-discovery,smb-enum-shares \
                -Pn "$target" 2>/dev/null | sed -n '/PORT/,$p')"
        if grep -qiE 'share|account_used|smb-os-discovery' <<< "$nse"; then
            record_finding "MEDIUM" "SMB" "SMB information gathered via nmap NSE" \
"Command: nmap -p ${port} --script smb-os-discovery,smb-enum-shares -Pn ${target}
Output:
$(printf '%s\n' "$nse" | head -20)" \
                "Exposed SMB OS/share details help an attacker fingerprint and target the host." \
                "Restrict anonymous SMB, disable SMBv1, and patch the OS."
        else
            record_finding "INFO" "SMB" "SMB present; nmap NSE returned limited data" \
                "nmap smb-* scripts against ${target}:${port} returned no share/OS details." \
                "Limited disclosure is preferable." \
                "Keep SMB authenticated and patched."
        fi
        return 0
    fi

    # ---- No tool available --------------------------------------------------
    log_info "Neither smbclient nor nmap available for SMB enumeration."
    record_finding "INFO" "SMB" "SMB enumeration skipped (no tool)" \
        "SMB is open on ${target}:${port} but no smbclient/nmap is installed to enumerate it." \
        "Informational — reflects the scanning host, not the target." \
        "Install smbclient to enable share enumeration."
    return 0
}
