#!/usr/bin/env bash
# =============================================================================
#  secscan.sh  —  Bash-Based Security Assessment Tool
# -----------------------------------------------------------------------------
#  A mini automated security-assessment framework in Bash. It takes a target,
#  performs reconnaissance, port & service enumeration, automated
#  service-specific checks, and produces a structured, evidence-based report.
#
#  USAGE
#      ./secscan.sh <target>            # scan a single host (IP or hostname)
#      ./secscan.sh targets.txt         # scan every host listed in a file
#      ./secscan.sh --full <target>     # full TCP port scan (all 65535 ports)
#      ./secscan.sh --zone lab.local <target>   # hint a DNS zone for AXFR
#      ./secscan.sh --help | --version
#
#  RULES OF ENGAGEMENT
#      Only scan systems you own or are explicitly authorised to test
#      (local lab VMs / authorised CTF environments). Never scan third-party
#      hosts without written permission.
#
#  DESIGN
#      secscan.sh is the orchestrator. Each capability lives in modules/*.sh and
#      is sourced here. The main script parses arguments, checks dependencies,
#      loops over targets, drives each phase, and dispatches the right service
#      module based on what the port scan actually discovered.
# =============================================================================

# Several globals below (TARGET, SCAN_TXT, FIND_*, RESOLVED_*, ...) are written
# here but consumed inside the modules sourced at runtime; shellcheck cannot
# trace them across the dynamic `source` loop, so silence the false positives.
# shellcheck disable=SC2034
set -o pipefail

# --- Constants ---------------------------------------------------------------
readonly VERSION="1.0.0"
readonly PROG="${0##*/}"
# Assign separately from `readonly` so a failure in cd/pwd isn't masked (SC2155).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly MODULE_DIR="${SCRIPT_DIR}/modules"
readonly REPORT_ROOT="${SCRIPT_DIR}/reports"

# --- Exit codes (meaningful, per the brief) ----------------------------------
readonly EXIT_OK=0
readonly EXIT_USAGE=1
readonly EXIT_DEPS=2
readonly EXIT_UNREACHABLE=3

# --- Options (defaults) ------------------------------------------------------
NMAP_PORT_ARGS=""          # consumed by portscan.sh ("-p-" for --full)
DNS_ZONE=""                # consumed by dns.sh
FORCE=0                    # scan even if ICMP reachability fails

# =============================================================================
#  Load modules
# =============================================================================
load_modules() {
    local m
    for m in utils recon portscan ftp ssh smb smtp dns http report; do
        local path="${MODULE_DIR}/${m}.sh"
        if [[ ! -r "$path" ]]; then
            printf '[-] Required module not found: %s\n' "$path" >&2
            exit $EXIT_DEPS
        fi
        # shellcheck source=/dev/null
        source "$path"
    done
}

# =============================================================================
#  Help / version
# =============================================================================
print_version() { printf '%s version %s\n' "$PROG" "$VERSION"; }

print_help() {
    cat <<EOF
$PROG $VERSION — Bash-Based Security Assessment Tool

USAGE:
    ./$PROG <target>              Scan a single IP address or hostname
    ./$PROG <targets.txt>         Scan every host listed in a file (one per line)

OPTIONS:
    --full            Full TCP port scan (nmap -p-, all 65535 ports; slower)
    --zone <name>     DNS zone name to try for a zone-transfer (AXFR) check
    --force           Continue scanning even if the host does not answer ICMP
    -h, --help        Show this help and exit
    -v, --version     Show version and exit

PHASES:
    1. Reconnaissance         host availability, IP/hostname, network info
    2. Port & service enum    nmap TCP scan + version detection, parsed to data
    3. Automated enumeration  per-service checks (FTP/SSH/SMB/SMTP/DNS/HTTP)
    4. Report generation      scan.txt, findings.txt, summary.txt, report.html

OUTPUT:
    reports/<target>_<timestamp>/

RULES OF ENGAGEMENT:
    Only scan systems you own or are explicitly authorised to test.

EXAMPLES:
    ./$PROG 192.168.56.10
    ./$PROG --full 192.168.56.10
    ./$PROG --zone lab.local 192.168.56.10
    ./$PROG targets.txt
EOF
}

usage_error() {
    printf 'Usage: ./%s <target>\n' "$PROG" >&2
    exit $EXIT_USAGE
}

# =============================================================================
#  Dependency check — nmap is the one hard requirement.
# =============================================================================
check_core_deps() {
    if ! command -v nmap >/dev/null 2>&1; then
        printf '[-] nmap is not installed\n' >&2
        printf '    Install it first, e.g.:  sudo apt install nmap\n' >&2
        exit $EXIT_DEPS
    fi
}

# =============================================================================
#  Per-target state reset (so multi-target runs stay independent)
# =============================================================================
reset_state() {
    OPEN_PORTS=()
    SERVICE_BY_PORT=()
    VERSION_BY_PORT=()
    FIND_SEVERITY=(); FIND_SERVICE=(); FIND_TITLE=()
    FIND_EVIDENCE=(); FIND_RISK=(); FIND_REC=()
    SEV_COUNT=( [CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0 [INFO]=0 )
    RESOLVED_IP=""; RESOLVED_HOST=""
}

# =============================================================================
#  Service dispatch — decide what to run from what was discovered.
#  This is the core "decision-making" logic: the branch is driven by the
#  service name nmap reported for each open port, not by a fixed assumption.
# =============================================================================
dispatch_services() {
    local target="$1" port svc
    local smb_done=0

    log_section "Automated Service Enumeration — $target"

    for port in "${OPEN_PORTS[@]}"; do
        svc="${SERVICE_BY_PORT[$port]}"
        case "$svc" in
            ftp|ftp-data)
                ftp_check "$port" "$target" ;;
            ssh)
                ssh_check "$port" "$target" ;;
            smtp|smtps|submission)
                smtp_check "$port" "$target" ;;
            domain)
                dns_check "$port" "$target" ;;
            microsoft-ds|netbios-ssn|netbios-ns)
                # SMB is one logical service even across ports 139/445 — run once.
                if [[ $smb_done -eq 0 ]]; then
                    smb_check "$port" "$target"; smb_done=1
                fi ;;
            http|https|http-proxy|http-alt|ssl/http|ssl/https|https-alt)
                # Runs PER web port, so 3 web ports => 3 independent HTTP scans.
                http_check "$port" "$target" ;;
            *)
                if [[ "$svc" == *http* ]]; then
                    http_check "$port" "$target"
                else
                    log_info "No dedicated module for '$svc' on port $port."
                    record_finding "INFO" "${svc:-unknown}" "Service present (no dedicated module)" \
                        "Port ${port}/tcp open running '${svc}' (version: ${VERSION_BY_PORT[$port]:-unknown}); no automated module covers it." \
                        "Unreviewed services can still be vulnerable." \
                        "Manually review ${svc} on port ${port}."
                fi ;;
        esac
    done
}

# =============================================================================
#  Scan one target end-to-end.
# =============================================================================
scan_target() {
    local target="$1"
    TARGET="$target"          # global — the report module reads $TARGET
    reset_state

    # Per-target, timestamped output directory.
    SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S %Z')"
    local ts safe
    ts="$(date '+%Y%m%d_%H%M%S')"
    safe="$(printf '%s' "$target" | tr -c 'A-Za-z0-9._-' '_')"
    OUT_DIR="${REPORT_ROOT}/${safe}_${ts}"
    mkdir -p "$OUT_DIR" || { log_error "Cannot create output dir $OUT_DIR"; return 1; }

    # File handles used across modules.
    SCAN_TXT="${OUT_DIR}/scan.txt"
    FINDINGS_TXT="${OUT_DIR}/findings.txt"
    SUMMARY_TXT="${OUT_DIR}/summary.txt"
    HTML_REPORT="${OUT_DIR}/report.html"
    LOG_FILE="${OUT_DIR}/scan.log"

    # Initialise the raw scan file + log.
    {
        echo "secscan.sh v${VERSION} — raw scan output"
        echo "Target : ${target}"
        echo "Date   : ${SCAN_DATE}"
        echo
    } > "$SCAN_TXT"
    _write_log "START" "Scan started for ${target}"

    printf '\n%s%s########## secscan: %s ##########%s\n' "$C_BOLD" "$C_BLUE" "$target" "$C_RESET"

    # --- Phase 1: recon ------------------------------------------------------
    if ! recon_run "$target"; then
        if [[ $FORCE -eq 1 ]]; then
            log_info "Host unreachable via ICMP, but --force set: continuing anyway."
        else
            log_error "Target is unreachable"
            log_info  "If the host blocks ICMP but has open ports, re-run with --force."
            _write_log "END" "Aborted — ${target} unreachable"
            return $EXIT_UNREACHABLE
        fi
    fi

    # --- Phase 2: port & service enumeration --------------------------------
    portscan_run "$target"
    local ps_rc=$?
    if [[ $ps_rc -eq 1 ]]; then
        # nmap missing — cannot proceed with this target.
        return $EXIT_DEPS
    fi

    # --- Phase 3: automated enumeration (only if we found ports) ------------
    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        dispatch_services "$target"
    fi

    # --- Phase 4: reporting --------------------------------------------------
    report_generate

    # Console summary line.
    log_section "Done — $target"
    printf '   Open ports : %s\n' "${OPEN_PORTS[*]:-none}"
    printf '   Findings   : CRIT %s / HIGH %s / MED %s / LOW %s / INFO %s\n' \
        "${SEV_COUNT[CRITICAL]}" "${SEV_COUNT[HIGH]}" "${SEV_COUNT[MEDIUM]}" \
        "${SEV_COUNT[LOW]}" "${SEV_COUNT[INFO]}"
    printf '   Reports    : %s/\n' "$OUT_DIR"
    _write_log "END" "Scan finished for ${target}"
    return $EXIT_OK
}

# =============================================================================
#  Argument parsing
# =============================================================================
main() {
    local -a positionals=()

    # No arguments at all -> usage error (brief requirement).
    [[ $# -eq 0 ]] && usage_error

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)    print_help;    exit $EXIT_OK ;;
            -v|--version) print_version; exit $EXIT_OK ;;
            --full)       NMAP_PORT_ARGS="-p-"; shift ;;
            --force)      FORCE=1; shift ;;
            --zone)
                [[ -n "${2:-}" ]] || { printf '[-] --zone needs a value\n' >&2; exit $EXIT_USAGE; }
                DNS_ZONE="$2"; shift 2 ;;
            --)           shift; while [[ $# -gt 0 ]]; do positionals+=("$1"); shift; done ;;
            -*)
                printf '[-] Unknown option: %s\n' "$1" >&2
                usage_error ;;
            *)            positionals+=("$1"); shift ;;
        esac
    done

    [[ ${#positionals[@]} -eq 0 ]] && usage_error

    # Modules define log_*, so load them before the banner. nmap check first
    # gives the exact required "[-] nmap is not installed" message early.
    check_core_deps
    load_modules

    # Export option globals so sourced modules see them.
    export NMAP_PORT_ARGS DNS_ZONE

    mkdir -p "$REPORT_ROOT"

    # --- Build the target list ----------------------------------------------
    # If the single positional is a readable file, treat it as a targets list
    # (bonus: multiple-target support). Otherwise treat positionals as targets.
    local -a targets=()
    if [[ ${#positionals[@]} -eq 1 && -f "${positionals[0]}" ]]; then
        log_info "Reading targets from file: ${positionals[0]}"
        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"                       # strip comments
            line="${line//[[:space:]]/}"             # strip whitespace
            [[ -n "$line" ]] && targets+=("$line")
        done < "${positionals[0]}"
    else
        targets=("${positionals[@]}")
    fi

    if [[ ${#targets[@]} -eq 0 ]]; then
        log_error "No valid targets to scan."
        exit $EXIT_USAGE
    fi

    # --- Loop over targets ---------------------------------------------------
    local t rc worst=0 count=0
    for t in "${targets[@]}"; do
        count=$((count+1))
        scan_target "$t"
        rc=$?
        [[ $rc -ne 0 ]] && worst=$rc
    done

    log_info "Completed ${count} target(s)."
    # Non-fatal per-target problems are surfaced via the worst return code.
    exit $worst
}

main "$@"
