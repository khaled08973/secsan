#!/usr/bin/env bash
# =============================================================================
# modules/ftp.sh  —  FTP service checks
#   Primary check: anonymous login (the classic FTP misconfiguration).
#   Evidence: the actual banner + the directory listing returned as "anonymous".
# =============================================================================
[[ -n "${__FTP_SH_LOADED:-}" ]] && return 0
__FTP_SH_LOADED=1

# grab_banner TARGET PORT  — read the first line a service sends on connect.
# Uses bash's built-in /dev/tcp (zero external dependencies) and a read timeout,
# so it returns as soon as the banner line arrives (FTP/SSH/SMTP all send one
# immediately) and gives up after a few seconds for services that stay silent.
grab_banner() {
    local target="$1" port="$2" line=""
    { exec 3<>"/dev/tcp/${target}/${port}"; } 2>/dev/null || { printf ''; return 0; }
    IFS= read -r -t 5 line <&3 2>/dev/null
    exec 3>&- 2>/dev/null
    printf '%s' "${line%$'\r'}"
}

# ftp_check PORT TARGET
ftp_check() {
    local port="$1" target="$2"
    log_detect "FTP detected on port $port"
    log_action "Starting FTP enumeration..."

    # --- Banner --------------------------------------------------------------
    local banner
    banner="$(grab_banner "$target" "$port")"
    if [[ -n "$banner" ]]; then
        log_info "FTP banner: $banner"
        record_finding "INFO" "FTP" "FTP service banner disclosed" \
            "Banner on ${target}:${port} -> ${banner}" \
            "Version banners let an attacker match the exact software against known CVEs." \
            "Suppress or genericise the FTP banner where the server allows it."
    fi

    # --- Anonymous login -----------------------------------------------------
    if ! have_cmd curl; then
        log_info "curl not available — skipping anonymous-login check."
        record_finding "INFO" "FTP" "Anonymous login check skipped" \
            "curl is not installed on the scanning host, so the automated anonymous-login test could not run." \
            "The check is informational only; absence of a tool is not a target weakness." \
            "Install curl (or the ftp client) to enable this check."
        return 0
    fi

    local listing rc
    # --ftp-method nocwd keeps the session simple; creds are anonymous/<any>.
    listing="$(run_capture 15 curl -s --ftp-method nocwd \
                --connect-timeout 8 \
                --user 'anonymous:secscan@example.com' \
                "ftp://${target}:${port}/")"
    rc=$?

    if [[ $rc -eq 0 ]]; then
        local sample
        sample="$(printf '%s\n' "$listing" | head -8)"
        [[ -z "$sample" ]] && sample="(login succeeded; root directory returned an empty listing)"
        log_finding "Anonymous FTP login ALLOWED"
        record_finding "HIGH" "FTP" "Anonymous FTP login allowed" \
"Command: curl --user 'anonymous:<any>' ftp://${target}:${port}/
Result : login succeeded (curl exit 0). Directory listing returned:
${sample}" \
            "Anonymous access can expose confidential files and, if any directory is writable, allows attackers to upload malicious content or web shells." \
            "Disable anonymous FTP (e.g. anonymous_enable=NO in vsftpd), or restrict it to a locked-down, read-only jail with no sensitive data."
    else
        log_info "Anonymous FTP login rejected (curl exit $rc)."
        record_finding "INFO" "FTP" "Anonymous FTP login rejected" \
            "curl --user 'anonymous:<any>' ftp://${target}:${port}/ failed (exit $rc) — server refused anonymous access." \
            "Refusing anonymous access is the correct, secure behaviour." \
            "No action required for anonymous access; still ensure strong credentials and FTPS/SFTP for real accounts."
    fi
    return 0
}
