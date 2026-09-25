#!/usr/bin/env bash
# =============================================================================
# modules/smtp.sh  —  SMTP service checks
#   Checks:
#     1) User enumeration via the VRFY verb (manual SMTP conversation).
#     2) Open-relay test (nmap smtp-open-relay NSE, if available).
#   The SMTP conversation is done with bash's /dev/tcp so it needs no extra
#   tools. We never send a message body (we QUIT before DATA) — this only
#   probes configuration, it does not relay real mail.
# =============================================================================
[[ -n "${__SMTP_SH_LOADED:-}" ]] && return 0
__SMTP_SH_LOADED=1

# smtp_converse TARGET PORT  — run a short scripted SMTP dialogue, print the
# full server-side transcript. Uses timed writes so replies line up in order.
smtp_converse() {
    local target="$1" port="$2"
    run_capture 25 bash -c '
        t="$1"; p="$2"
        exec 3<>/dev/tcp/"$t"/"$p" || exit 1
        cat <&3 &                       # background reader -> stdout (captured)
        cpid=$!
        sleep 0.6
        printf "EHLO secscan.local\r\n"                >&3; sleep 0.8
        printf "VRFY root\r\n"                          >&3; sleep 0.8
        printf "VRFY zzUnlikelyUser987\r\n"             >&3; sleep 0.8
        printf "MAIL FROM:<audit@secscan.local>\r\n"    >&3; sleep 0.8
        printf "RCPT TO:<relaytest@example.org>\r\n"    >&3; sleep 0.8
        printf "QUIT\r\n"                               >&3; sleep 0.8
        kill "$cpid" 2>/dev/null
    ' _ "$target" "$port" | tr -d '\r'
}

# smtp_check PORT TARGET
smtp_check() {
    local port="$1" target="$2"
    log_detect "SMTP detected on port $port"
    log_action "Starting SMTP enumeration..."

    # --- Banner --------------------------------------------------------------
    local banner
    banner="$(grab_banner "$target" "$port")"
    [[ -n "$banner" ]] && log_info "SMTP banner: $banner"

    # --- VRFY / conversation -------------------------------------------------
    local transcript
    transcript="$(smtp_converse "$target" "$port")"
    if [[ -z "$transcript" ]]; then
        log_info "No SMTP transcript captured."
        record_finding "INFO" "SMTP" "SMTP present; no transcript" \
            "A scripted SMTP dialogue with ${target}:${port} returned no data within the timeout." \
            "Inconclusive." \
            "Retry manually with: nc ${target} ${port}"
        return 0
    fi

    local snippet
    snippet="$(printf '%s\n' "$transcript" | grep -E '^[0-9]{3}' | head -12)"
    [[ -z "$snippet" ]] && snippet="$(printf '%s\n' "$transcript" | head -12)"

    # VRFY verdict: a 250/252 reply to VRFY indicates the verb is answered.
    if printf '%s\n' "$transcript" | grep -qiE 'Vrfy|^25[02] .*(root|user|<)'; then
        record_finding "MEDIUM" "SMTP" "SMTP VRFY user enumeration appears enabled" \
"Scripted dialogue (EHLO + VRFY root + VRFY bogus). Server transcript:
${snippet}" \
            "If VRFY distinguishes valid from invalid users, an attacker can harvest valid account names for password attacks." \
            "Disable the VRFY/EXPN verbs (e.g. Postfix: disable_vrfy_command = yes)."
    else
        record_finding "INFO" "SMTP" "SMTP VRFY does not clearly leak users" \
"Server transcript (codes):
${snippet}" \
            "VRFY either disabled or returns a uniform code — good posture." \
            "Keep VRFY/EXPN disabled and require authentication for mail submission."
    fi

    # --- Open relay (nmap NSE) ----------------------------------------------
    if have_cmd nmap; then
        local relay
        relay="$(run_capture 60 nmap -p "$port" --script smtp-open-relay -Pn "$target" 2>/dev/null \
                 | sed -n '/smtp-open-relay/,/^$/p')"
        if grep -qi 'is an open relay' <<< "$relay"; then
            record_finding "CRITICAL" "SMTP" "SMTP server is an OPEN RELAY" \
"Command: nmap -p ${port} --script smtp-open-relay -Pn ${target}
Result:
$(printf '%s\n' "$relay" | head -10)" \
                "An open relay lets anyone send mail through this server — leading to spam blacklisting, spoofing and abuse." \
                "Restrict relaying to authenticated users / trusted networks only (mynetworks / smtpd_relay_restrictions)."
        elif grep -qiE 'not an open relay|couldn.t' <<< "$relay"; then
            record_finding "INFO" "SMTP" "SMTP relay test: not an open relay" \
                "nmap smtp-open-relay reported the server is not relaying for external senders." \
                "Correct, secure behaviour." \
                "No action needed for relaying."
        fi
    else
        log_info "nmap not available — skipping open-relay NSE test."
    fi
    return 0
}
