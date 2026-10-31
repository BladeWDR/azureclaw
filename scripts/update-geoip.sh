#!/usr/bin/env bash
# /usr/libexec/azureclaw/update-geoip.sh
# Downloads MaxMind GeoLite2-Country.mmdb via geoipupdate and compiles
# country CIDR blocks into native nftables interval sets (/etc/nftables.d/30-geoip.nft).

set -euo pipefail

GEOIP_CONF="/etc/GeoIP.conf"
BLOCK_CONF="/etc/azureclaw/geoip-block.conf"
NFT_GEOIP_FILE="/etc/nftables.d/30-geoip.nft"
NFT_MAIN_FILE="/etc/nftables/nftables.conf"
GEOIP_DIR="/var/lib/GeoIP"

mkdir -p "$GEOIP_DIR" /etc/nftables.d

# 1. Load configuration safely
GEOIP_ENABLED="false"
GEOIP_MODE="block"
GEOIP_COUNTRIES=""
GEOIP_DIRECTION="both"
GEOIP_MMDB_PATH="/var/lib/GeoIP/GeoLite2-Country.mmdb"

if [[ -f "$BLOCK_CONF" ]]; then
    while IFS='=' read -r raw_key raw_val; do
        # Strip comments and whitespace
        key="$(echo "${raw_key%%#*}" | tr -d '[:space:]')"
        [[ -z "$key" ]] && continue
        val="$(echo "${raw_val%%#*}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
        case "$key" in
            GEOIP_ENABLED)   GEOIP_ENABLED="$val" ;;
            GEOIP_MODE)      GEOIP_MODE="$val" ;;
            GEOIP_COUNTRIES) GEOIP_COUNTRIES="$val" ;;
            GEOIP_DIRECTION) GEOIP_DIRECTION="$val" ;;
            GEOIP_MMDB_PATH) GEOIP_MMDB_PATH="$val" ;;
        esac
    done < "$BLOCK_CONF"
fi

# 2. If disabled or no countries configured, remove active GeoIP ruleset and exit cleanly
if [[ "${GEOIP_ENABLED,,}" != "true" ]] || [[ -z "${GEOIP_COUNTRIES// /}" ]]; then
    if [[ -f "$NFT_GEOIP_FILE" ]]; then
        echo "[azureclaw-geoip] GeoIP filtering disabled; removing $NFT_GEOIP_FILE"
        rm -f "$NFT_GEOIP_FILE"
        if systemctl is-active --quiet nftables; then
            systemctl reload nftables || true
        fi
    else
        echo "[azureclaw-geoip] GeoIP filtering is disabled in $BLOCK_CONF."
    fi
    exit 0
fi

# 3. Run geoipupdate if MaxMind credentials are configured in /etc/GeoIP.conf
if [[ -f "$GEOIP_CONF" ]] && ! grep -qE "YOUR_ACCOUNT_ID_HERE|YOUR_LICENSE_KEY_HERE" "$GEOIP_CONF"; then
    echo "[azureclaw-geoip] Running geoipupdate to refresh MaxMind database..."
    if ! geoipupdate -f "$GEOIP_CONF" -d "$GEOIP_DIR"; then
        echo "[azureclaw-geoip] WARNING: geoipupdate failed; checking for cached database at $GEOIP_MMDB_PATH" >&2
    fi
else
    echo "[azureclaw-geoip] Notice: MaxMind credentials not yet set in $GEOIP_CONF; checking for local database at $GEOIP_MMDB_PATH"
fi

if [[ ! -f "$GEOIP_MMDB_PATH" ]]; then
    echo "[azureclaw-geoip] ERROR: MaxMind database not found at $GEOIP_MMDB_PATH." >&2
    echo "[azureclaw-geoip] Configure AccountID and LicenseKey in $GEOIP_CONF and re-run." >&2
    exit 1
fi

# 4. Generate /etc/nftables.d/30-geoip.nft from MaxMind MMDB using python3-maxminddb
TMP_NFT="$(mktemp /etc/nftables.d/.30-geoip.nft.XXXXXX)"
trap 'rm -f "$TMP_NFT"' EXIT

python3 - "$GEOIP_MMDB_PATH" "$GEOIP_MODE" "$GEOIP_DIRECTION" "$GEOIP_COUNTRIES" "$TMP_NFT" << 'PYEOF'
import ipaddress
import re
import sys
import maxminddb

mmdb_path, mode, direction, raw_countries, out_path = sys.argv[1:6]

mode = mode.strip().lower()
if mode not in ("block", "allow"):
    sys.exit(f"Invalid GEOIP_MODE '{mode}'. Must be 'block' or 'allow'.")

direction = direction.strip().lower()
if direction not in ("inbound", "outbound", "both"):
    sys.exit(f"Invalid GEOIP_DIRECTION '{direction}'. Must be 'inbound', 'outbound', or 'both'.")

tokens = [t.strip().upper() for t in re.split(r"[\s,]+", raw_countries) if t.strip()]
countries = sorted(set(tokens))
for c in countries:
    if not re.match(r"^[A-Z]{2}$", c):
        sys.exit(f"Invalid ISO 3166-1 alpha-2 country code: '{c}'")

if not countries:
    sys.exit("No valid country codes specified.")

target_set = set(countries)
v4_nets = []
v6_nets = []

with maxminddb.open_database(mmdb_path) as reader:
    for network, record in reader:
        if not isinstance(record, dict):
            continue
        iso = (
            (record.get("country") or {}).get("iso_code")
            or (record.get("registered_country") or {}).get("iso_code")
            or ""
        ).upper()
        if iso in target_set:
            if isinstance(network, ipaddress.IPv4Network):
                v4_nets.append(network)
            elif isinstance(network, ipaddress.IPv6Network):
                v6_nets.append(network)

v4_collapsed = list(ipaddress.collapse_addresses(v4_nets))
v6_collapsed = list(ipaddress.collapse_addresses(v6_nets))

print(
    f"[azureclaw-geoip] Extracted {len(v4_collapsed)} IPv4 and {len(v6_collapsed)} IPv6 "
    f"aggregated CIDR blocks for countries: {', '.join(countries)}"
)

def format_elements(nets):
    if not nets:
        return ""
    lines = []
    chunk = []
    for net in nets:
        chunk.append(str(net))
        if len(chunk) >= 8:
            lines.append("            " + ", ".join(chunk) + ",")
            chunk = []
    if chunk:
        lines.append("            " + ", ".join(chunk))
    return "\n".join(lines)

v4_elements_block = ""
if v4_collapsed:
    v4_elements_block = f"        elements = {{\n{format_elements(v4_collapsed)}\n        }}"

v6_elements_block = ""
if v6_collapsed:
    v6_elements_block = f"        elements = {{\n{format_elements(v6_collapsed)}\n        }}"

input_rules = []
forward_rules = []

if mode == "block":
    if direction in ("inbound", "both"):
        if v4_collapsed:
            input_rules.append('        iifname $WAN_IFACES ip saddr @geoip_v4 drop comment "GeoIP Inbound Block IPv4"')
            forward_rules.append('        iifname $WAN_IFACES ip saddr @geoip_v4 drop comment "GeoIP Forward Inbound Block IPv4"')
        if v6_collapsed:
            input_rules.append('        iifname $WAN_IFACES ip6 saddr @geoip_v6 drop comment "GeoIP Inbound Block IPv6"')
            forward_rules.append('        iifname $WAN_IFACES ip6 saddr @geoip_v6 drop comment "GeoIP Forward Inbound Block IPv6"')
    if direction in ("outbound", "both"):
        if v4_collapsed:
            forward_rules.append('        oifname $WAN_IFACES ip daddr @geoip_v4 drop comment "GeoIP Outbound Egress Block IPv4"')
        if v6_collapsed:
            forward_rules.append('        oifname $WAN_IFACES ip6 daddr @geoip_v6 drop comment "GeoIP Outbound Egress Block IPv6"')
else:
    # Allowlist mode: exempt RFC1918/CGNAT/link-local so upstream ISP gateway/DHCP traffic is never dropped
    if direction in ("inbound", "both"):
        input_rules.append('        iifname $WAN_IFACES ip saddr { 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16 } return')
        input_rules.append('        iifname $WAN_IFACES ip6 saddr { fe80::/10, fc00::/7 } return')
        forward_rules.append('        iifname $WAN_IFACES ip saddr { 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16 } return')
        forward_rules.append('        iifname $WAN_IFACES ip6 saddr { fe80::/10, fc00::/7 } return')
        if v4_collapsed:
            input_rules.append('        iifname $WAN_IFACES ip saddr != @geoip_v4 drop comment "GeoIP Inbound Allowlist IPv4"')
            forward_rules.append('        iifname $WAN_IFACES ip saddr != @geoip_v4 drop comment "GeoIP Forward Inbound Allowlist IPv4"')
        if v6_collapsed:
            input_rules.append('        iifname $WAN_IFACES ip6 saddr != @geoip_v6 drop comment "GeoIP Inbound Allowlist IPv6"')
            forward_rules.append('        iifname $WAN_IFACES ip6 saddr != @geoip_v6 drop comment "GeoIP Forward Inbound Allowlist IPv6"')
    if direction in ("outbound", "both"):
        forward_rules.append('        oifname $WAN_IFACES ip daddr { 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16 } return')
        forward_rules.append('        oifname $WAN_IFACES ip6 daddr { fe80::/10, fc00::/7 } return')
        if v4_collapsed:
            forward_rules.append('        oifname $WAN_IFACES ip daddr != @geoip_v4 drop comment "GeoIP Outbound Allowlist IPv4"')
        if v6_collapsed:
            forward_rules.append('        oifname $WAN_IFACES ip6 daddr != @geoip_v6 drop comment "GeoIP Outbound Allowlist IPv6"')

content = f"""# Azureclaw MaxMind GeoIP Firewall Set
# Auto-generated by /usr/libexec/azureclaw/update-geoip.sh — DO NOT EDIT MANUALLY
# Mode: {mode} | Direction: {direction} | Countries: {' '.join(countries)}

table inet router {{
    set geoip_v4 {{
        type ipv4_addr
        flags interval
        auto-merge
{v4_elements_block}
    }}

    set geoip_v6 {{
        type ipv6_addr
        flags interval
        auto-merge
{v6_elements_block}
    }}

    chain geoip_input {{
{chr(10).join(input_rules)}
    }}

    chain geoip_forward {{
{chr(10).join(forward_rules)}
    }}
}}
"""

with open(out_path, "w", encoding="utf-8") as f:
    f.write(content)
PYEOF

chmod 0644 "$TMP_NFT"

# 5. Install and validate with nft -c before reloading
BACKUP_NFT=""
if [[ -f "$NFT_GEOIP_FILE" ]]; then
    BACKUP_NFT="$(mktemp /etc/nftables.d/.30-geoip.backup.XXXXXX)"
    cp -a "$NFT_GEOIP_FILE" "$BACKUP_NFT"
fi

mv -f "$TMP_NFT" "$NFT_GEOIP_FILE"

if nft -c -f "$NFT_MAIN_FILE"; then
    rm -f "${BACKUP_NFT:-}"
    if systemctl is-active --quiet nftables; then
        systemctl reload nftables
    fi
    echo "[azureclaw-geoip] Successfully validated and applied $NFT_GEOIP_FILE."
else
    echo "[azureclaw-geoip] ERROR: nftables validation failed! Rolling back $NFT_GEOIP_FILE." >&2
    if [[ -n "$BACKUP_NFT" && -f "$BACKUP_NFT" ]]; then
        mv -f "$BACKUP_NFT" "$NFT_GEOIP_FILE"
    else
        rm -f "$NFT_GEOIP_FILE"
    fi
    exit 1
fi
