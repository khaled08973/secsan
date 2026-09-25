#!/usr/bin/env bash
# =============================================================================
# modules/http.sh  —  HTTP / HTTPS service checks
#   Checks: response headers, server banner, security headers, robots.txt,
#           page title, CMS fingerprint (e.g. WordPress), directory listing.
#   Requires curl. Handles both http and https (self-signed lab certs -> -k).
# =============================================================================
[[ -n "${__HTTP_SH_LOADED:-}" ]] && return 0
__HTTP_SH_LOADED=1

# http_scheme_for PORT SERVICE  — echo "https" or "http".
http_scheme_for() {
    local port="$1" service="$2"
    if [[ "$service" == *ssl* || "$service" == *https* || "$port" == "443" || "$port" == "8443" ]]; then
        echo "https"
    else
        echo "http"
    fi
}

# http_check PORT TARGET
http_check() {
    local port="$1" target="$2"
    local service="${SERVICE_BY_PORT[$port]:-http}"
    local scheme; scheme="$(http_scheme_for "$port" "$service")"
    local base="${scheme}://${target}:${port}"

    log_detect "HTTP detected on port $port (${scheme})"
    log_action "Starting HTTP enumeration on ${base} ..."

    if ! have_cmd curl; then
        log_info "curl not installed — skipping HTTP checks."
        record_finding "INFO" "HTTP" "HTTP checks skipped (curl missing)" \
            "HTTP is open on ${base} but curl is not installed on the scanning host." \
            "Informational — reflects the scanner, not the target." \
            "Install curl to enable HTTP enumeration."
        return 0
    fi

    # --- Response headers ----------------------------------------------------
    local headers
    headers="$(run_capture 15 curl -sk -m 12 -D - -o /dev/null "$base/")"
    if [[ -z "$headers" ]]; then
        log_info "No HTTP response received."
        record_finding "INFO" "HTTP" "No HTTP response" \
            "curl -I ${base}/ returned nothing within the timeout." \
            "Inconclusive." "Retry manually: curl -Ik ${base}/"
        return 0
    fi

    local statusline server
    statusline="$(printf '%s\n' "$headers" | head -1 | tr -d '\r')"
    server="$(printf '%s\n' "$headers" | grep -i '^Server:' | head -1 | tr -d '\r')"
    log_info "Status: $statusline"
    [[ -n "$server" ]] && log_info "$server"

    record_finding "INFO" "HTTP" "HTTP response headers captured" \
"Request: curl -I ${base}/
Status : ${statusline}
${server:-Server: (not sent)}" \
        "Baseline fingerprint of the web server." \
        "Review the full header set below for version/security-header issues."

    # --- Server banner discloses version? -----------------------------------
    if [[ "$server" =~ [0-9]+\.[0-9]+ ]]; then
        record_finding "LOW" "HTTP" "Web server version disclosed" \
            "${server} (from ${base}/)" \
            "Precise version banners let attackers match known CVEs quickly." \
            "Suppress version tokens (Apache: ServerTokens Prod / ServerSignature Off; Nginx: server_tokens off)."
    fi

    # --- Missing security headers -------------------------------------------
    local -a missing=()
    grep -qi '^X-Frame-Options:'         <<< "$headers" || missing+=("X-Frame-Options")
    grep -qi '^X-Content-Type-Options:'  <<< "$headers" || missing+=("X-Content-Type-Options")
    grep -qi '^Content-Security-Policy:'  <<< "$headers" || missing+=("Content-Security-Policy")
    if [[ "$scheme" == "https" ]]; then
        grep -qi '^Strict-Transport-Security:' <<< "$headers" || missing+=("Strict-Transport-Security")
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        record_finding "LOW" "HTTP" "Missing HTTP security headers" \
            "Absent on ${base}/: ${missing[*]}" \
            "Missing headers make clickjacking, MIME-sniffing and injection attacks easier." \
            "Add the missing response headers at the web server or application layer."
    fi

    # --- robots.txt ----------------------------------------------------------
    local robots
    robots="$(run_capture 12 curl -sk -m 10 "$base/robots.txt")"
    if [[ -n "$robots" ]] && grep -qiE 'Disallow|Allow|User-agent' <<< "$robots"; then
        local dis
        dis="$(grep -iE 'Disallow|Allow' <<< "$robots" | head -10)"
        record_finding "LOW" "HTTP" "robots.txt discloses paths" \
"${base}/robots.txt returned:
${dis}" \
            "robots.txt often reveals admin panels or hidden directories worth probing." \
            "Do not rely on robots.txt for security; protect sensitive paths with authentication."
    fi

    # --- Page title & CMS fingerprint ---------------------------------------
    local body title
    body="$(run_capture 15 curl -sk -m 12 "$base/")"
    title="$(printf '%s' "$body" | grep -ioE '<title>[^<]*</title>' | head -1 | sed -E 's/<\/?title>//gI')"
    [[ -n "$title" ]] && log_info "Page title: $title"

    if grep -qiE 'wp-content|wp-includes|/wp-login|WordPress' <<< "$body$headers"; then
        record_finding "MEDIUM" "HTTP" "WordPress detected" \
"Fingerprints found in ${base}/ (e.g. wp-content / wp-login references)${title:+; title: \"$title\"}." \
            "WordPress core/plugins/themes are a large, frequently-vulnerable attack surface; wp-login.php enables password attacks." \
            "Enumerate plugin/theme versions, keep them patched, and protect wp-login.php (2FA, rate-limiting)."
    fi

    # --- Directory listing on common dirs -----------------------------------
    local d listing
    for d in / /files/ /uploads/ /backup/ /images/; do
        listing="$(run_capture 8 curl -sk -m 6 "${base}${d}")"
        if grep -qiE '<title>Index of|Directory listing for' <<< "$listing"; then
            record_finding "MEDIUM" "HTTP" "Directory listing enabled" \
                "Auto-index is enabled at ${base}${d} (\"Index of\" page returned)." \
                "Directory listing exposes files not meant to be public (backups, configs, source)." \
                "Disable auto-indexing (Apache: Options -Indexes; Nginx: autoindex off)."
            break
        fi
    done
    return 0
}
