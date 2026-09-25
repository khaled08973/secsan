#!/usr/bin/env bash
# =============================================================================
# modules/utils.sh
# -----------------------------------------------------------------------------
# Shared helpers used by every other module:
#   - terminal colours (auto-disabled when output is not a TTY)
#   - console message helpers ([*] [+] [!] [-]) that ALSO append to the log file
#   - timestamped logging to a per-scan log file
#   - dependency checks (have_cmd / need_cmd)
#   - the central finding recorder (record_finding) + evidence store
#
# This file only DEFINES functions/variables. It never runs anything on its own,
# so it is safe to `source` it from secscan.sh.
# =============================================================================

# Guard against being sourced twice (each module sources what it needs).
[[ -n "${__UTILS_SH_LOADED:-}" ]] && return 0
__UTILS_SH_LOADED=1

# -----------------------------------------------------------------------------
# Colours — only enable them when stdout is an interactive terminal and the
# user has not set NO_COLOR. Reports written to files therefore stay clean.
# -----------------------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'
    C_RED=$'\e[31m';  C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'
    C_BLUE=$'\e[34m'; C_CYAN=$'\e[36m';  C_GREY=$'\e[90m'
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""
    C_BLUE=""; C_CYAN=""; C_GREY=""
fi

# LOG_FILE is set by secscan.sh once the per-scan output directory exists.
# Until then it is empty and the log helpers simply skip file writes.
: "${LOG_FILE:=}"

# -----------------------------------------------------------------------------
# _write_log LEVEL MESSAGE
#   Append a single timestamped line to the log file, if one is configured.
# -----------------------------------------------------------------------------
_write_log() {
    local level="$1"; shift
    [[ -n "$LOG_FILE" ]] || return 0
    printf '%s [%-6s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*" >> "$LOG_FILE"
}

# -----------------------------------------------------------------------------
# Console message helpers. Each prints a coloured, prefixed line to the console
# and mirrors a plain copy into the log file so the run is fully auditable.
#   log_action  [*]  something is being started / in progress   (cyan)
#   log_detect  [+]  a service / positive result was found      (green)
#   log_finding [!]  a security-relevant finding / alert        (yellow)
#   log_error   [-]  an error condition                         (red, -> stderr)
#   log_info    [i]  neutral informational note                 (grey)
# -----------------------------------------------------------------------------
log_action()  { printf '%s[*]%s %s\n' "$C_CYAN"   "$C_RESET" "$*"; _write_log "ACTION"  "$*"; }
log_detect()  { printf '%s[+]%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; _write_log "DETECT"  "$*"; }
log_finding() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; _write_log "FINDING" "$*"; }
log_error()   { printf '%s[-]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; _write_log "ERROR" "$*"; }
log_info()    { printf '%s[i]%s %s\n' "$C_GREY"   "$C_RESET" "$*"; _write_log "INFO"    "$*"; }

# A visual section header for the console (also logged).
log_section() {
    printf '\n%s%s==> %s%s\n' "$C_BOLD" "$C_BLUE" "$*" "$C_RESET"
    _write_log "SECTION" "$*"
}

# -----------------------------------------------------------------------------
# Dependency checks.
#   have_cmd CMD   -> returns 0 if CMD is on PATH, 1 otherwise (no output)
#   need_cmd  CMD  -> like have_cmd but logs an error if missing (returns 1)
# -----------------------------------------------------------------------------
have_cmd() { command -v "$1" >/dev/null 2>&1; }

need_cmd() {
    if have_cmd "$1"; then
        return 0
    fi
    log_error "$1 is not installed"
    return 1
}

# -----------------------------------------------------------------------------
# Finding storage.
# Findings are collected in parallel indexed arrays during the scan and turned
# into the report files at the end (see modules/report.sh). Keeping them in
# memory lets us produce the txt report, the summary and the HTML report from a
# single source of truth.
# -----------------------------------------------------------------------------
# NOTE: -g (global) is essential — this file is sourced from inside a function
# (load_modules), and a plain `declare` there would create function-local arrays
# that vanish on return. -g forces them into the global scope.
declare -ga FIND_SEVERITY=()   # INFO | LOW | MEDIUM | HIGH | CRITICAL
declare -ga FIND_SERVICE=()    # e.g. FTP, SSH, HTTP
declare -ga FIND_TITLE=()      # short human title
declare -ga FIND_EVIDENCE=()   # concrete evidence (may contain \n)
declare -ga FIND_RISK=()       # why it matters
declare -ga FIND_REC=()        # what to do about it

# Count of findings by severity, for the summary line.
declare -gA SEV_COUNT=( [CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0 [INFO]=0 )

# -----------------------------------------------------------------------------
# record_finding SEVERITY SERVICE TITLE EVIDENCE RISK RECOMMENDATION
#   Store one evidence-backed finding and echo it to the console immediately so
#   the operator sees decisions as they happen. Every finding MUST carry
#   evidence — that is the core grading criterion.
# -----------------------------------------------------------------------------
record_finding() {
    local sev="$1" service="$2" title="$3" evidence="$4" risk="$5" rec="$6"

    FIND_SEVERITY+=( "$sev" )
    FIND_SERVICE+=(  "$service" )
    FIND_TITLE+=(    "$title" )
    FIND_EVIDENCE+=( "$evidence" )
    FIND_RISK+=(     "$risk" )
    FIND_REC+=(      "$rec" )

    # Bump the per-severity counter (default to INFO if an odd value slips in).
    if [[ -n "${SEV_COUNT[$sev]+x}" ]]; then
        SEV_COUNT[$sev]=$(( SEV_COUNT[$sev] + 1 ))
    else
        SEV_COUNT[INFO]=$(( SEV_COUNT[INFO] + 1 ))
    fi

    # Immediate console feedback (indented evidence under the title).
    log_finding "[$sev] $service: $title"
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] && printf '      %s%s%s\n' "$C_GREY" "$line" "$C_RESET"
    done <<< "$evidence"
}

# -----------------------------------------------------------------------------
# strip_ansi  — read stdin, remove any ANSI colour codes, write stdout.
# Used when we want tool output stored cleanly in a report file.
# -----------------------------------------------------------------------------
strip_ansi() { sed -r 's/\x1b\[[0-9;]*m//g'; }

# -----------------------------------------------------------------------------
# run_capture OUTVAR CMD [ARGS...]  (helper for timeouts)
# Runs a command with a sane timeout so a hung service can never freeze the
# whole assessment. Prints combined stdout+stderr. Returns the command's code
# (124 if it timed out).
# -----------------------------------------------------------------------------
run_capture() {
    local seconds="$1"; shift
    if have_cmd timeout; then
        timeout "$seconds" "$@" 2>&1
    else
        "$@" 2>&1
    fi
}
