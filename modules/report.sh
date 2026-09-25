#!/usr/bin/env bash
# =============================================================================
# modules/report.sh  —  Phase 4.5 Report Generation
#   Turns the in-memory findings (utils.sh arrays) + captured scan output into:
#     reports/<target>_<ts>/scan.txt      (raw scan evidence — appended earlier)
#     reports/<target>_<ts>/findings.txt  (structured, evidence-backed findings)
#     reports/<target>_<ts>/summary.txt   (executive summary)
#     reports/<target>_<ts>/report.html   (bonus: HTML report)
#   Each report includes: Target, Scan date, Open ports, Detected services,
#   Findings with evidence, Risk explanation, Recommendations.
# =============================================================================
[[ -n "${__REPORT_SH_LOADED:-}" ]] && return 0
__REPORT_SH_LOADED=1

# Numeric rank so we can sort findings most-severe first.
_sev_rank() {
    case "$1" in
        CRITICAL) echo 0 ;; HIGH) echo 1 ;; MEDIUM) echo 2 ;;
        LOW) echo 3 ;; *) echo 4 ;;
    esac
}

# Echo finding indices ordered by severity (most severe first).
_findings_by_severity() {
    local i
    for i in "${!FIND_SEVERITY[@]}"; do
        printf '%s %s\n' "$(_sev_rank "${FIND_SEVERITY[$i]}")" "$i"
    done | sort -n -k1,1 -s | awk '{print $2}'
}

# Overall risk word from the highest severity present.
_overall_risk() {
    if   (( SEV_COUNT[CRITICAL] > 0 )); then echo "CRITICAL"
    elif (( SEV_COUNT[HIGH]     > 0 )); then echo "HIGH"
    elif (( SEV_COUNT[MEDIUM]   > 0 )); then echo "MEDIUM"
    elif (( SEV_COUNT[LOW]      > 0 )); then echo "LOW"
    else echo "INFORMATIONAL"; fi
}

_services_list() {
    local p out=""
    for p in "${OPEN_PORTS[@]}"; do
        out+="${p}/${SERVICE_BY_PORT[$p]} "
    done
    echo "${out:-none}"
}

# HTML-escape stdin.
_html_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# -----------------------------------------------------------------------------
# report_write_findings  -> findings.txt
# -----------------------------------------------------------------------------
report_write_findings() {
    local f="$FINDINGS_TXT" i n=0
    {
        echo "======================================================================"
        echo " FINDINGS  —  ${TARGET}"
        echo " Generated: ${SCAN_DATE}"
        echo "======================================================================"
        echo
        if [[ ${#FIND_SEVERITY[@]} -eq 0 ]]; then
            echo "No findings were recorded."
        fi
    } > "$f"

    for i in $(_findings_by_severity); do
        n=$((n+1))
        {
            echo "[${FIND_SEVERITY[$i]}] #${n} — ${FIND_SERVICE[$i]}: ${FIND_TITLE[$i]}"
            echo "  Evidence:"
            printf '%s\n' "${FIND_EVIDENCE[$i]}" | sed 's/^/    /'
            echo "  Risk:"
            printf '%s\n' "${FIND_RISK[$i]}" | sed 's/^/    /'
            echo "  Recommendation:"
            printf '%s\n' "${FIND_REC[$i]}" | sed 's/^/    /'
            echo "----------------------------------------------------------------------"
        } >> "$f"
    done
}

# -----------------------------------------------------------------------------
# report_write_summary  -> summary.txt
# -----------------------------------------------------------------------------
report_write_summary() {
    local f="$SUMMARY_TXT" p i
    {
        echo "======================================================================"
        echo " SECURITY ASSESSMENT SUMMARY"
        echo "======================================================================"
        echo "Target            : ${TARGET}  (${RESOLVED_IP})"
        echo "Hostname / PTR    : ${RESOLVED_HOST}"
        echo "Scan date         : ${SCAN_DATE}"
        echo "Open TCP ports    : ${OPEN_PORTS[*]:-none}"
        echo "Detected services : $(_services_list)"
        echo
        echo "Findings by severity:"
        printf '  CRITICAL: %s   HIGH: %s   MEDIUM: %s   LOW: %s   INFO: %s\n' \
            "${SEV_COUNT[CRITICAL]}" "${SEV_COUNT[HIGH]}" "${SEV_COUNT[MEDIUM]}" \
            "${SEV_COUNT[LOW]}" "${SEV_COUNT[INFO]}"
        echo
        echo "Overall risk      : $(_overall_risk)"
        echo
        echo "----------------------------------------------------------------------"
        echo " Risk explanation"
        echo "----------------------------------------------------------------------"
        case "$(_overall_risk)" in
            CRITICAL|HIGH)
                echo " The target exposes at least one high-impact misconfiguration that could"
                echo " give an attacker unauthorised access or a foothold. Prioritise the"
                echo " CRITICAL/HIGH findings below immediately." ;;
            MEDIUM)
                echo " No single critical issue was confirmed, but several medium-risk"
                echo " weaknesses together widen the attack surface and aid an attacker." ;;
            LOW)
                echo " Only low-risk information-disclosure issues were found. Individually"
                echo " minor, but worth hardening as defence-in-depth." ;;
            *)
                echo " No security weaknesses were confirmed by the automated checks. This is"
                echo " not proof of a secure host — only that these specific checks passed." ;;
        esac
        echo
        echo "----------------------------------------------------------------------"
        echo " Top recommendations"
        echo "----------------------------------------------------------------------"
        # List recommendations for the most severe findings first (dedup lightly).
        local shown=0
        for i in $(_findings_by_severity); do
            [[ "${FIND_SEVERITY[$i]}" == "INFO" ]] && continue
            echo " - [${FIND_SEVERITY[$i]}] ${FIND_SERVICE[$i]}: ${FIND_REC[$i]}"
            shown=$((shown+1))
            [[ $shown -ge 10 ]] && break
        done
        [[ $shown -eq 0 ]] && echo " - Maintain current configuration; keep all services patched."
    } > "$f"
}

# -----------------------------------------------------------------------------
# report_write_html  -> report.html  (bonus)
# -----------------------------------------------------------------------------
report_write_html() {
    local f="$HTML_REPORT" i n=0 risk
    risk="$(_overall_risk)"

    cat > "$f" <<HTMLHEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>secscan report — ${TARGET}</title>
<style>
  :root{ --bg:#0f1419; --card:#1a2029; --fg:#e6edf3; --muted:#9aa7b4;
         --crit:#ff4d4f; --high:#ff7a45; --med:#faad14; --low:#40a9ff; --info:#8c8c8c;
         --line:#2b333d; }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
       font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;}
  .wrap{max-width:960px;margin:0 auto;padding:28px 18px 60px;}
  h1{font-size:24px;margin:0 0 4px} h2{font-size:18px;margin:28px 0 12px;
     border-bottom:1px solid var(--line);padding-bottom:6px}
  .sub{color:var(--muted);margin:0 0 18px}
  table{width:100%;border-collapse:collapse;margin:6px 0 12px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:13px;text-transform:uppercase;letter-spacing:.04em}
  .meta td:first-child{color:var(--muted);width:170px}
  .badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:12px;
         font-weight:700;color:#08111a}
  .CRITICAL{background:var(--crit);color:#fff} .HIGH{background:var(--high)}
  .MEDIUM{background:var(--med)} .LOW{background:var(--low)} .INFO{background:var(--info);color:#fff}
  .finding{background:var(--card);border:1px solid var(--line);border-radius:10px;
           padding:14px 16px;margin:12px 0}
  .finding h3{margin:0 0 8px;font-size:16px;display:flex;gap:10px;align-items:center}
  .finding .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;margin-top:10px}
  pre{background:#0b0f14;border:1px solid var(--line);border-radius:8px;
      padding:10px 12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;
      font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#c9d5e1}
  .riskbanner{padding:12px 16px;border-radius:10px;font-weight:700;margin:8px 0 4px}
  footer{color:var(--muted);font-size:12px;margin-top:40px;border-top:1px solid var(--line);padding-top:14px}
</style>
</head>
<body><div class="wrap">
  <h1>Security Assessment Report</h1>
  <p class="sub">Generated by <strong>secscan.sh</strong> — automated, evidence-based lab assessment</p>

  <h2>Overview</h2>
  <table class="meta">
    <tr><td>Target</td><td>$(printf '%s' "$TARGET" | _html_escape) ($(printf '%s' "$RESOLVED_IP" | _html_escape))</td></tr>
    <tr><td>Hostname / PTR</td><td>$(printf '%s' "$RESOLVED_HOST" | _html_escape)</td></tr>
    <tr><td>Scan date</td><td>${SCAN_DATE}</td></tr>
    <tr><td>Open TCP ports</td><td>${OPEN_PORTS[*]:-none}</td></tr>
    <tr><td>Detected services</td><td>$(_services_list | _html_escape)</td></tr>
  </table>

  <div class="riskbanner ${risk}">Overall risk: ${risk}
    &nbsp;·&nbsp; CRITICAL ${SEV_COUNT[CRITICAL]} · HIGH ${SEV_COUNT[HIGH]} · MEDIUM ${SEV_COUNT[MEDIUM]} · LOW ${SEV_COUNT[LOW]} · INFO ${SEV_COUNT[INFO]}</div>

  <h2>Open Ports &amp; Services</h2>
  <table>
    <tr><th>Port</th><th>Service</th><th>Version</th></tr>
HTMLHEAD

    local p
    for p in "${OPEN_PORTS[@]}"; do
        {
            echo "    <tr><td>${p}/tcp</td><td>$(printf '%s' "${SERVICE_BY_PORT[$p]}" | _html_escape)</td><td>$(printf '%s' "${VERSION_BY_PORT[$p]:-—}" | _html_escape)</td></tr>"
        } >> "$f"
    done
    echo "  </table>" >> "$f"

    echo "  <h2>Findings</h2>" >> "$f"
    if [[ ${#FIND_SEVERITY[@]} -eq 0 ]]; then
        echo "  <p class='sub'>No findings were recorded.</p>" >> "$f"
    fi
    for i in $(_findings_by_severity); do
        n=$((n+1))
        {
            echo "  <div class='finding'>"
            echo "    <h3><span class='badge ${FIND_SEVERITY[$i]}'>${FIND_SEVERITY[$i]}</span> #${n} · $(printf '%s' "${FIND_SERVICE[$i]}" | _html_escape) — $(printf '%s' "${FIND_TITLE[$i]}" | _html_escape)</h3>"
            echo "    <div class='lbl'>Evidence</div>"
            echo "    <pre>$(printf '%s' "${FIND_EVIDENCE[$i]}" | _html_escape)</pre>"
            echo "    <div class='lbl'>Risk</div><div>$(printf '%s' "${FIND_RISK[$i]}" | _html_escape)</div>"
            echo "    <div class='lbl'>Recommendation</div><div>$(printf '%s' "${FIND_REC[$i]}" | _html_escape)</div>"
            echo "  </div>"
        } >> "$f"
    done

    cat >> "$f" <<HTMLFOOT
  <footer>secscan.sh · report generated ${SCAN_DATE} · for authorised lab testing only.</footer>
</div></body></html>
HTMLFOOT
}

# -----------------------------------------------------------------------------
# report_generate  — produce every report artifact and tell the user where.
# -----------------------------------------------------------------------------
report_generate() {
    log_section "Report Generation"
    report_write_findings
    report_write_summary
    report_write_html
    log_detect "Reports written to: ${OUT_DIR}/"
    log_info   " - scan.txt      (raw scan evidence)"
    log_info   " - findings.txt  (evidence-backed findings)"
    log_info   " - summary.txt   (executive summary)"
    log_info   " - report.html   (HTML report)"
}
