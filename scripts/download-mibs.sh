#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  SNMP Manager — MIB Database Downloader
#  Avtomatik ravishda RFC standart, vendor va community MIB fayllarni
#  yuklab olib, /usr/share/snmp/mibs/ ga o'rnatadi.
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────
MIB_BASE="/usr/share/snmp/mibs"
MIB_EXTRA="${MIB_BASE}/extra"
MIB_VENDOR="${MIB_BASE}/vendor"
TMP_DIR=$(mktemp -d /tmp/mib-download.XXXXXX)
LOG_FILE="/tmp/mib-download.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
TOTAL_DOWNLOADED=0
TOTAL_SKIPPED=0
TOTAL_ERRORS=0

# ── Helper Functions ──────────────────────────────────────────────────

log_info()  { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_err()   { echo -e "${RED}[✗]${NC} $*"; }
log_step()  { echo -e "\n${CYAN}${BOLD}═══ $* ═══${NC}"; }

download_file() {
    local url="$1"
    local dest="$2"
    local name
    name=$(basename "$dest")

    if [[ -f "$dest" ]]; then
        ((TOTAL_SKIPPED++))
        return 0
    fi

    if curl -fsSL --connect-timeout 10 --max-time 30 -o "$dest" "$url" 2>>"$LOG_FILE"; then
        # Validate — MIB files should contain DEFINITIONS or MODULE
        if grep -qiE '(DEFINITIONS|MODULE-IDENTITY|OBJECT-TYPE|IMPORTS)' "$dest" 2>/dev/null; then
            ((TOTAL_DOWNLOADED++))
            return 0
        else
            rm -f "$dest"
            ((TOTAL_ERRORS++))
            return 1
        fi
    else
        rm -f "$dest"
        ((TOTAL_ERRORS++))
        return 1
    fi
}

download_github_dir() {
    local repo="$1"      # e.g. "user/repo"
    local branch="$2"    # e.g. "main"
    local path="$3"      # e.g. "mibs"
    local dest_dir="$4"
    local api_url="https://api.github.com/repos/${repo}/contents/${path}?ref=${branch}"

    local file_list
    file_list=$(curl -fsSL --connect-timeout 10 "$api_url" 2>>"$LOG_FILE" | \
        grep '"download_url"' | \
        sed 's/.*"download_url": *"//;s/".*//' | \
        grep -iE '\.(txt|mib|my)$' || true)

    if [[ -z "$file_list" ]]; then
        return 1
    fi

    local count=0
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        local fname
        fname=$(basename "$url")
        download_file "$url" "${dest_dir}/${fname}" && ((count++)) || true
    done <<< "$file_list"

    echo "$count"
}

# ── Pre-flight Checks ────────────────────────────────────────────────

log_step "MIB Database Downloader"
echo -e "Vaqt: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "MIB papka: ${MIB_BASE}"

if [[ $EUID -ne 0 ]]; then
    # Detect project root (script is in scripts/ subdirectory)
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    log_warn "Root emas — MIB fayllar ${PROJECT_DIR}/mibs/ ga yuklanadi"
    log_warn "Root bilan ishga tushirsangiz /usr/share/snmp/mibs/ ga yoziladi"
    MIB_BASE="${PROJECT_DIR}/mibs"
    MIB_EXTRA="${MIB_BASE}/extra"
    MIB_VENDOR="${MIB_BASE}/vendor"
fi

mkdir -p "$MIB_BASE" "$MIB_EXTRA" "$MIB_VENDOR"
echo "" > "$LOG_FILE"

# Check dependencies
for cmd in curl grep sed; do
    if ! command -v "$cmd" &>/dev/null; then
        log_err "$cmd topilmadi. O'rnating: sudo pacman -S $cmd"
        exit 1
    fi
done

# ── 1. Standard RFC MIBs (IETF) ──────────────────────────────────────

log_step "1/5 — Standart RFC MIBlar (IETF)"

RFC_MIBS=(
    # Core MIBs
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMPv2-SMI.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMPv2-TC.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMPv2-CONF.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMPv2-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMPv2-TM.txt"
    # Interfaces
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/IF-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/IF-INVERTED-STACK-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/IANAifType-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/EtherLike-MIB.txt"
    # IP / Routing
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/IP-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/IP-FORWARD-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/TCP-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/UDP-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/INET-ADDRESS-MIB.txt"
    # Bridge / VLAN
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/BRIDGE-MIB.txt"
    # Host Resources
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/HOST-RESOURCES-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/HOST-RESOURCES-TYPES.txt"
    # Entity
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/NOTIFICATION-LOG-MIB.txt"
    # SNMP Framework
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMP-FRAMEWORK-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMP-TARGET-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMP-NOTIFICATION-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMP-USER-BASED-SM-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMP-VIEW-BASED-ACM-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMP-COMMUNITY-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMP-MPD-MIB.txt"
    # RMON
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/RMON-MIB.txt"
    # Tunnel
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/TUNNEL-MIB.txt"
    # UCD (Linux)
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/UCD-SNMP-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/UCD-DISKIO-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/LM-SENSORS-MIB.txt"
    # Net-SNMP extras
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/NET-SNMP-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/NET-SNMP-AGENT-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/NET-SNMP-EXTEND-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/NET-SNMP-TC.txt"
)

for url in "${RFC_MIBS[@]}"; do
    fname=$(basename "$url")
    download_file "$url" "${MIB_BASE}/${fname}" || true
done
log_info "RFC MIBlar: ${TOTAL_DOWNLOADED} yangi, ${TOTAL_SKIPPED} mavjud"

# ── 2. Extended RFC MIBs (ENTITY, LLDP, Q-BRIDGE, POWER) ─────────────

log_step "2/5 — Kengaytirilgan MIBlar (ENTITY, LLDP, VLAN, PoE)"

EXTENDED_MIBS=(
    # ENTITY-MIB (hardware inventory)
    "https://raw.githubusercontent.com/hardaker/net-snmp/master/mibs/ENTITY-MIB.txt"
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/ENTITY-MIB.my"
    # LLDP - Link Layer Discovery Protocol
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/LLDP-MIB.my"
    # Q-BRIDGE-MIB (VLANs)
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/Q-BRIDGE-MIB.my"
    # POWER-ETHERNET-MIB (PoE)
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/POWER-ETHERNET-MIB.my"
    # ENTITY-SENSOR-MIB (temperature, fans)
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/ENTITY-SENSOR-MIB.my"
    # MAU-MIB (Ethernet speed/duplex)
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/MAU-MIB.my"
    # DISMAN-EVENT-MIB
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/DISMAN-EVENT-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/DISMAN-SCHEDULE-MIB.txt"
    # IPV6
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/IPV6-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/IPV6-ICMP-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/IPV6-TCP-MIB.txt"
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/IPV6-UDP-MIB.txt"
    # SCTP
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SCTP-MIB.txt"
    # AGENTX
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/AGENTX-MIB.txt"
)

before=$TOTAL_DOWNLOADED
for url in "${EXTENDED_MIBS[@]}"; do
    fname=$(basename "$url")
    # Normalize .my → .txt
    fname="${fname%.my}.txt"
    download_file "$url" "${MIB_EXTRA}/${fname}" || true
done
ext_count=$((TOTAL_DOWNLOADED - before))
log_info "Kengaytirilgan MIBlar: ${ext_count} yangi yuklab olindi"

# ── 3. Community MIB Collections ─────────────────────────────────────

log_step "3/5 — Community MIB to'plamlari"

# STP / RSTP
COMMUNITY_MIBS=(
    # OSPF
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/OSPF-MIB.my"
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/OSPF-TRAP-MIB.my"
    # BGP
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/BGP4-MIB.my"
    # RSTP
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/RSTP-MIB.my"
    # VRRP
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/VRRP-MIB.my"
    # IEEE 802.1X
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/IEEE8021-PAE-MIB.my"
    # Network Services
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/NETWORK-SERVICES-MIB.my"
    # SNMPv2 Party (legacy)
    "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/SNMP-REPEATER-MIB.my"
)

before=$TOTAL_DOWNLOADED
for url in "${COMMUNITY_MIBS[@]}"; do
    fname=$(basename "$url")
    fname="${fname%.my}.txt"
    download_file "$url" "${MIB_EXTRA}/${fname}" || true
done
comm_count=$((TOTAL_DOWNLOADED - before))
log_info "Community MIBlar: ${comm_count} yangi yuklab olindi"

# ── 4. Vendor-Specific MIBs ──────────────────────────────────────────

log_step "4/5 — Vendor MIBlar"

# --- Eltex ---
log_info "Eltex MIBlar yuklanmoqda..."
mkdir -p "${MIB_VENDOR}/eltex"

ELTEX_MIBS=(
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-MES-PHYSICAL-DESCRIPTION-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-MES-ISS-CPU-UTIL-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-MES-TRAPS-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-MES-ENV-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-MES-HARDWARE-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-MES-FAN-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-MES-NG"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-MES-SYSLOG-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-MES-COPY-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-PHY-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-BASE-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/eltex/ELTEX-SMI-ACTUAL"
)

before=$TOTAL_DOWNLOADED
for url in "${ELTEX_MIBS[@]}"; do
    fname=$(basename "$url")
    [[ "$fname" != *.txt ]] && fname="${fname}.txt"
    download_file "$url" "${MIB_VENDOR}/eltex/${fname}" || true
done
eltex_count=$((TOTAL_DOWNLOADED - before))
log_info "Eltex: ${eltex_count} MIB yuklab olindi"

# --- MikroTik ---
log_info "MikroTik MIBlar yuklanmoqda..."
mkdir -p "${MIB_VENDOR}/mikrotik"

MIKROTIK_MIBS=(
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/mikrotik/MIKROTIK-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/mikrotik/MIKROTIK-MIB.txt"
)

before=$TOTAL_DOWNLOADED
for url in "${MIKROTIK_MIBS[@]}"; do
    fname=$(basename "$url")
    [[ "$fname" != *.txt ]] && fname="${fname}.txt"
    download_file "$url" "${MIB_VENDOR}/mikrotik/${fname}" || true
done
mt_count=$((TOTAL_DOWNLOADED - before))
log_info "MikroTik: ${mt_count} MIB yuklab olindi"

# --- Huawei ---
log_info "Huawei MIBlar yuklanmoqda..."
mkdir -p "${MIB_VENDOR}/huawei"

HUAWEI_MIBS=(
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/huawei/HUAWEI-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/huawei/HUAWEI-ENTITY-EXTENT-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/huawei/HUAWEI-ENERGYMNGT-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/huawei/HUAWEI-SWITCH-SRV-RES-TRAP-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/huawei/HUAWEI-PORT-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/huawei/HUAWEI-TC-MIB"
)

before=$TOTAL_DOWNLOADED
for url in "${HUAWEI_MIBS[@]}"; do
    fname=$(basename "$url")
    [[ "$fname" != *.txt ]] && fname="${fname}.txt"
    download_file "$url" "${MIB_VENDOR}/huawei/${fname}" || true
done
hw_count=$((TOTAL_DOWNLOADED - before))
log_info "Huawei: ${hw_count} MIB yuklab olindi"

# --- D-Link ---
log_info "D-Link MIBlar yuklanmoqda..."
mkdir -p "${MIB_VENDOR}/dlink"

DLINK_MIBS=(
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/dlink/DLINK-EQUIPMENT-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/dlink/EQUIPMENT-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/dlink/SAFEGUARD-ENGINE-MIB"
)

before=$TOTAL_DOWNLOADED
for url in "${DLINK_MIBS[@]}"; do
    fname=$(basename "$url")
    [[ "$fname" != *.txt ]] && fname="${fname}.txt"
    download_file "$url" "${MIB_VENDOR}/dlink/${fname}" || true
done
dl_count=$((TOTAL_DOWNLOADED - before))
log_info "D-Link: ${dl_count} MIB yuklab olindi"

# ── 5. LibreNMS Community MIBs (keng to'plam) ────────────────────────

log_step "5/5 — LibreNMS keng MIB to'plami"
log_info "LibreNMS dan qo'shimcha umumiy MIBlar yuklanmoqda..."

LIBRENMS_COMMON=(
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/ENTITY-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/ENTITY-SENSOR-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/LLDP-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/Q-BRIDGE-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/POWER-ETHERNET-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/IEEE8021-PAE-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/RSTP-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/BGP4-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/OSPF-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/VRRP-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/MAU-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/CISCO-SMI"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/IEEE8023-LAG-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/IPMROUTE-STD-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/MPLS-TC-STD-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/P-BRIDGE-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/RADIUS-AUTH-CLIENT-MIB"
    "https://raw.githubusercontent.com/librenms/librenms/master/mibs/SNMP-FRAMEWORK-MIB"
)

before=$TOTAL_DOWNLOADED
for url in "${LIBRENMS_COMMON[@]}"; do
    fname=$(basename "$url")
    [[ "$fname" != *.txt ]] && fname="${fname}.txt"
    download_file "$url" "${MIB_EXTRA}/${fname}" || true
done
ln_count=$((TOTAL_DOWNLOADED - before))
log_info "LibreNMS: ${ln_count} MIB yuklab olindi"

# ── Summary ───────────────────────────────────────────────────────────

log_step "Natija"

total_files=$(find "$MIB_BASE" -type f \( -name '*.txt' -o -name '*.mib' -o -name '*.my' \) 2>/dev/null | wc -l)

echo -e ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         MIB Database Statistikasi        ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC} Yangi yuklab olindi:  ${GREEN}${TOTAL_DOWNLOADED}${NC}"
echo -e "${BOLD}║${NC} Allaqachon mavjud:    ${YELLOW}${TOTAL_SKIPPED}${NC}"
echo -e "${BOLD}║${NC} Xatoliklar:           ${RED}${TOTAL_ERRORS}${NC}"
echo -e "${BOLD}║${NC} Jami MIB fayllar:     ${CYAN}${total_files}${NC}"
echo -e "${BOLD}║${NC}"
echo -e "${BOLD}║${NC} MIB papkalar:"
echo -e "${BOLD}║${NC}   ${MIB_BASE}/"
echo -e "${BOLD}║${NC}   ${MIB_EXTRA}/"
echo -e "${BOLD}║${NC}   ${MIB_VENDOR}/"
echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}"
echo -e ""

# Show vendor breakdown
if [[ -d "$MIB_VENDOR" ]]; then
    echo -e "${BOLD}Vendor MIBlar:${NC}"
    for vendor_dir in "${MIB_VENDOR}"/*/; do
        if [[ -d "$vendor_dir" ]]; then
            vendor_name=$(basename "$vendor_dir")
            vendor_count=$(find "$vendor_dir" -type f 2>/dev/null | wc -l)
            if [[ $vendor_count -gt 0 ]]; then
                echo -e "  📦 ${vendor_name}: ${vendor_count} fayl"
            fi
        fi
    done
    echo ""
fi

# Recommend config update
echo -e "${BOLD}config.yaml ga qo'shing:${NC}"
echo -e "${CYAN}mib:"
echo -e "  load_system_mibs: true"
echo -e "  directories:"
echo -e "    - \"${MIB_BASE}\""
echo -e "    - \"${MIB_EXTRA}\""
echo -e "    - \"${MIB_VENDOR}/eltex\""
echo -e "    - \"${MIB_VENDOR}/mikrotik\""
echo -e "    - \"${MIB_VENDOR}/huawei\""
echo -e "    - \"${MIB_VENDOR}/dlink\"${NC}"
echo ""

# Test with snmptranslate if available
if command -v snmptranslate &>/dev/null; then
    all_dirs="${MIB_BASE}:${MIB_EXTRA}:${MIB_VENDOR}/eltex:${MIB_VENDOR}/mikrotik"
    oid_count=$(MIBDIRS="$all_dirs" snmptranslate -m ALL -Tt 2>/dev/null | wc -l || echo "?")
    echo -e "${GREEN}snmptranslate bilan tekshiruv: ~${oid_count} OID taniladi${NC}"
fi

# Cleanup temp dir only
[[ -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
log_info "Tayyor! Servisni qayta ishga tushiring: sudo make dev"
