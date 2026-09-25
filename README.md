# secscan.sh — Bash-Based Security Assessment Tool

A mini **automated security-assessment framework** written in pure Bash. Given a
target, it runs through **reconnaissance → port & service enumeration → automated
service-specific checks → a structured, evidence-based report**.

It is deliberately **not a one-liner around `nmap`**: `nmap` is used only as the
scanning engine, and the real work — parsing its output into structured data,
deciding which checks to run per service, gathering evidence, scoring risk and
generating reports — is done in Bash.

> ⚠️ **Rules of engagement**
> Only scan systems you **own** or are **explicitly authorised** to test
> (local lab VMs, authorised CTF environments). Never scan third-party hosts or
> live public websites. Run lab VMs on an **isolated Host-only network**.

---

## Features

| | Feature |
|---|---|
| ✅ | **Reconnaissance** — host availability (ICMP), forward/reverse DNS, RTT |
| ✅ | **Port & service enumeration** — `nmap -sV`, parsed into structured Bash data |
| ✅ | **Automated, service-aware checks** — FTP, SSH, SMB, SMTP, DNS, HTTP/HTTPS |
| ✅ | **Evidence-based findings** — every finding carries the command + real output |
| ✅ | **Risk scoring** — CRITICAL / HIGH / MEDIUM / LOW / INFO with an overall rollup |
| ✅ | **Structured reports** — `scan.txt`, `findings.txt`, `summary.txt` |
| ⭐ | **Bonus:** HTML report (`report.html`) |
| ⭐ | **Bonus:** multiple-target support (`./secscan.sh targets.txt`) |
| ⭐ | **Bonus:** `--help` / `--version` flags |
| ⭐ | **Bonus:** modular architecture (`modules/*.sh`) |
| ⭐ | **Bonus:** deep, per-service enumeration modules |

---

## Requirements

| Tool | Needed for | Required? |
|------|------------|-----------|
| `bash` (4+) | everything | **yes** |
| `nmap` | port & service scanning | **yes** (hard dependency) |
| `dig` (`dnsutils`) | DNS checks / resolution | recommended |
| `curl` | FTP anonymous + HTTP checks | recommended |
| `smbclient` | SMB share enumeration | optional (falls back to nmap NSE) |
| `ping` | reachability | recommended |

The script **degrades gracefully**: if an optional tool is missing, the relevant
check is skipped with a clear note instead of crashing. Only `nmap` is fatal if
absent.

**Install everything on Debian/Ubuntu/Kali:**
```bash
sudo apt update
sudo apt install -y nmap dnsutils curl smbclient iputils-ping
```

---

## Installation

```bash
git clone https://github.com/<your-username>/secscan.git
cd secscan
chmod +x secscan.sh modules/*.sh
```

---

## Usage

```text
./secscan.sh <target>              Scan a single IP address or hostname
./secscan.sh <targets.txt>         Scan every host listed in a file (one per line)

Options:
  --full            Full TCP port scan (nmap -p-, all 65535 ports; slower)
  --zone <name>     DNS zone name to try for a zone-transfer (AXFR) check
  --force           Continue scanning even if the host does not answer ICMP
  -h, --help        Show help and exit
  -v, --version     Show version and exit
```

### Examples

```bash
./secscan.sh 192.168.56.10                 # standard scan
./secscan.sh --full 192.168.56.10          # all 65,535 TCP ports
./secscan.sh --zone lab.local 192.168.56.10 # hint a zone for AXFR
./secscan.sh --force 192.168.56.10         # host filters ICMP but has open ports
./secscan.sh targets.txt                    # scan many hosts
```

---

## Output

Each run creates a timestamped directory under `reports/`:

```text
reports/192.168.56.10_20260924_201927/
├── scan.txt       # raw evidence: recon block + structured port table + nmap output
├── findings.txt   # every finding, most-severe first, with evidence/risk/fix
├── summary.txt     # executive summary: target, ports, services, risk, top fixes
├── report.html    # the same, as a styled HTML report (bonus)
└── scan.log       # timestamped run log (auditing)
```

Every report includes, as required by the brief:
**Target · Scan date · Open ports · Detected services · Findings with evidence ·
Risk explanation · Recommendations.**

### Example finding (from `findings.txt`)

```text
[HIGH] #1 — FTP: Anonymous FTP login allowed
  Evidence:
    Command: curl --user 'anonymous:<any>' ftp://192.168.56.10:21/
    Result : login succeeded (curl exit 0). Directory listing returned:
    -rw-r--r--   1 root  root   7 Sep 24 17:15 creds.txt
    drwxr-xr-x   2 root  root  4096 Sep 24 17:15 pub
  Risk:
    Anonymous access can expose confidential files and, if a directory is
    writable, allows attackers to upload web shells.
  Recommendation:
    Disable anonymous FTP (anonymous_enable=NO in vsftpd), or restrict it to a
    locked-down, read-only jail with no sensitive data.
```

---

## Architecture

```text
secscan/
├── secscan.sh          # orchestrator: args, deps, target loop, phase control, dispatch
├── modules/
│   ├── utils.sh        # colours, logging, dependency checks, finding recorder
│   ├── recon.sh        # 4.1 reconnaissance
│   ├── portscan.sh     # 4.2 nmap scan + greppable-output parser -> structured data
│   ├── ftp.sh          # anonymous-login check
│   ├── ssh.sh          # version / banner check
│   ├── smb.sh          # share enumeration (smbclient, nmap NSE fallback)
│   ├── smtp.sh         # VRFY user-enum + open-relay check
│   ├── dns.sh          # zone-transfer (AXFR) + version.bind
│   ├── http.sh         # headers, security headers, robots.txt, CMS, dir listing
│   └── report.sh       # 4.5 report generation (txt + html)
└── reports/            # generated output (git-ignored)
```

**Data model.** `portscan.sh` parses `nmap`'s greppable output into three global
structures the rest of the tool branches on:

```bash
OPEN_PORTS=(21 80 445)             # open TCP ports
SERVICE_BY_PORT[21]="ftp"          # port -> service
VERSION_BY_PORT[21]="vsftpd 2.3.4" # port -> version banner
```

**Decision logic.** `dispatch_services()` loops over every open port and calls the
module that matches the **service nmap actually reported** — not a fixed
assumption about port numbers. Findings are collected by `record_finding()` into
in-memory arrays, then `report.sh` renders all output from that single source of
truth.

---

## How the mandatory requirements are met

| Requirement | Where |
|---|---|
| **Functions** | every module is built from functions (e.g. `recon_run`, `portscan_parse_grep`, `record_finding`) |
| **Arguments** (`$1`, `$@`, …) | `main "$@"`, per-module `PORT`/`TARGET` params, `--zone <name>` |
| **Loops** | target loop, open-port loop in `dispatch_services`, token parsing, report generation |
| **Conditionals** | `if`/`case` throughout, especially the service dispatch `case` |
| **Exit codes** | `0` ok · `1` usage · `2` missing dependency · `3` unreachable |
| **Pipes / redirection** | nmap parsing, `tee -a` to reports, `>>` appends, here-docs |
| **File handling** | reads a targets file, writes `scan/findings/summary/html/log` |
| **Error handling & logging** | graceful tool-missing handling, timeouts, timestamped `scan.log` |

### Error handling (Advanced Requirements)

```bash
$ ./secscan.sh
Usage: ./secscan.sh <target>          # exit 1

$ ./secscan.sh 10.0.0.99
[-] Target is unreachable             # exit 3  (use --force to override)

$ ./secscan.sh 192.168.56.10          # (nmap absent)
[-] nmap is not installed             # exit 2

[+] SMB detected                       # clear decision-making output
[*] Starting SMB enumeration...
```

---

## Design notes (for the walkthrough)

- **"If the target had 3 different web ports, how would your script handle
  that?"** — `dispatch_services` runs `http_check` **per open port**, so ports
  80, 8080 and 8443 each get their own independent HTTP assessment (443/8443 are
  auto-treated as HTTPS with `curl -k` for self-signed lab certs).
- **Why parse greppable output?** — `nmap -oG` is line-oriented and stable, which
  makes `port/state/proto//service//version` trivial to split into the data model
  above, instead of scraping human-readable text.
- **Why `-Pn` in the scan?** — reachability is checked separately in the recon
  phase; many lab VMs filter ICMP but still expose services, so `-Pn` stops host
  discovery from skipping them. `--force` lets the whole run continue in that case.
- **Graceful degradation** — SMB tries `smbclient` first and falls back to
  `nmap`'s `smb-enum-shares` NSE script, so the check still works when
  `smbclient` isn't installed.
- **Evidence over labels** — every `record_finding` call stores the exact command
  run and its real output, so no finding is ever just a label.

---

## Tested against

Designed for the brief's suggested targets — **Metasploitable 2** (FTP/SMB/SMTP/
HTTP), **DC-6** (WordPress/SSH), **VulnOS: 1**, **SecOS: 1** — or any isolated lab
VM on a Host-only network.

---

## License

For educational use within the Instant Software Solutions — Security Track.
