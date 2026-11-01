#!/usr/bin/env bash
# /usr/libexec/azureclaw/onboarding-wizard.sh
# Interactive First-Login Network & DHCP Onboarding Wizard for Azureclaw
set -euo pipefail

MARKER="/var/lib/azureclaw/onboarding.done"
mkdir -p /var/lib/azureclaw

# Ensure script runs as root (re-exec via sudo if invoked by admin)
if [[ "${EUID}" -ne 0 ]]; then
    exec sudo /usr/libexec/azureclaw/onboarding-wizard.sh "$@"
fi

# -----------------------------------------------------------------------------
# Validation & Calculation Helpers
# -----------------------------------------------------------------------------
validate_ipv4() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    local IFS='.'
    read -r -a octets <<< "$ip"
    for o in "${octets[@]}"; do
        if (( 10#$o < 0 || 10#$o > 255 )); then
            return 1
        fi
    done
    return 0
}

validate_cidr() {
    local cidr="$1"
    local min="${2:-1}"
    local max="${3:-32}"
    [[ "$cidr" =~ ^[0-9]{1,2}$ ]] && (( 10#$cidr >= min && 10#$cidr <= max ))
}

cidr_to_netmask() {
    local cidr="$1"
    local mask=$(( (0xffffffff << (32 - cidr)) & 0xffffffff ))
    printf "%d.%d.%d.%d\n" \
        $(( (mask >> 24) & 255 )) \
        $(( (mask >> 16) & 255 )) \
        $(( (mask >> 8) & 255 )) \
        $(( mask & 255 ))
}

validate_domain() {
    local d="$1"
    [[ "$d" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]
}

# -----------------------------------------------------------------------------
# Discover Physical Network Interfaces
# -----------------------------------------------------------------------------
mapfile -t PHYS_IFACES < <(
    ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | while read -r dev; do
        [[ "$dev" == "lo" ]] && continue
        [[ "$dev" =~ ^(veth|br-|virbr|docker|podman|wg|tailscale|tun|tap|ppp|ipsec|xfrm|sit|gre|dummy) ]] && continue
        [[ "$dev" == *.* ]] && continue
        echo "$dev"
    done
)

if [[ "${#PHYS_IFACES[@]}" -eq 0 ]]; then
    PHYS_IFACES=("ens18" "ens19")
fi

clear_or_newline() {
    echo ""
}

clear_or_newline
cat << 'EOF'
========================================================================
   __ _ _____   _ _ __ ___  ___| | __ ___      __
  / _` |_  / | | | '__/ _ \/ __| |/ _` \ \ /\ / /
 | (_| |/ /| |_| | | |  __/ (__| | (_| |\ V  V / 
  \__,_/___|\__,_|_|  \___|\___|_|\__,_| \_/\_/  
       Interactive Router Onboarding Setup
========================================================================
EOF

if [[ "${1:-}" == "--first-login" ]] && [[ -f "$MARKER" ]]; then
    exit 0
fi

if [[ "${1:-}" == "--first-login" ]]; then
    echo " Welcome to Azureclaw! Let's configure your WAN, LAN, and DHCP settings."
    echo " (You can re-run this wizard anytime with: sudo azureclaw-setup)"
    echo ""
    read -r -p " Start interactive network setup now? [Y/n]: " start_ans
    case "${start_ans:-Y}" in
        [nN][oO]|[nN])
            read -r -p " Skip onboarding prompt on future logins? [y/N]: " skip_forever
            if [[ "${skip_forever:-N}" =~ ^[yY] ]]; then
                touch "$MARKER"
                echo " Onboarding marked complete. Run 'sudo azureclaw-setup' anytime."
            fi
            exit 0
            ;;
    esac
fi

echo ""
echo " Detected Physical Network Interfaces:"
echo " ----------------------------------------------------------------------"
for i in "${!PHYS_IFACES[@]}"; do
    dev="${PHYS_IFACES[$i]}"
    mac=$(cat "/sys/class/net/${dev}/address" 2>/dev/null || echo "unknown")
    oper=$(cat "/sys/class/net/${dev}/operstate" 2>/dev/null | tr '[:lower:]' '[:upper:]' || echo "UNKNOWN")
    curr_ip=$(ip -4 -br addr show dev "$dev" 2>/dev/null | awk '{print $3}' | head -n1 || true)
    printf "   %d) %-12s  State: %-6s  MAC: %-17s  %s\n" \
        $((i + 1)) "$dev" "$oper" "$mac" "${curr_ip:+IP: $curr_ip}"
done
echo " ----------------------------------------------------------------------"
echo ""

# -----------------------------------------------------------------------------
# 1. Select WAN Interface & Mode
# -----------------------------------------------------------------------------
DEFAULT_WAN="${PHYS_IFACES[0]}"
while true; do
    read -r -p " 1. Select WAN (Internet Uplink) interface [${DEFAULT_WAN}]: " wan_input
    wan_input="${wan_input:-$DEFAULT_WAN}"
    if [[ "$wan_input" =~ ^[0-9]+$ ]] && (( wan_input >= 1 && wan_input <= ${#PHYS_IFACES[@]} )); then
        WAN_IFACE="${PHYS_IFACES[$((wan_input - 1))]}"
        break
    elif printf '%s\n' "${PHYS_IFACES[@]}" | grep -qx "$wan_input"; then
        WAN_IFACE="$wan_input"
        break
    elif [[ "$wan_input" =~ ^[a-zA-Z0-9_-]{1,15}$ ]]; then
        WAN_IFACE="$wan_input"
        break
    else
        echo "    [!] Invalid selection. Enter a number (1-${#PHYS_IFACES[@]}) or interface name."
    fi
done

echo ""
echo "    WAN IPv4 Configuration Mode for '${WAN_IFACE}':"
echo "      1) DHCP (Automatic from ISP) [default]"
echo "      2) Static IPv4 (Manual IP, Subnet, Gateway, DNS)"
while true; do
    read -r -p "    Choose WAN mode [1]: " wan_mode_num
    wan_mode_num="${wan_mode_num:-1}"
    case "$wan_mode_num" in
        1|dhcp|DHCP|auto)
            WAN_MODE="auto"
            WAN_IP=""
            WAN_CIDR=""
            WAN_GW=""
            WAN_DNS=""
            break
            ;;
        2|static|STATIC|manual)
            WAN_MODE="manual"
            while true; do
                read -r -p "    Enter Static WAN IPv4 Address (e.g. 203.0.113.10): " WAN_IP
                validate_ipv4 "$WAN_IP" && break
                echo "    [!] Please enter a valid IPv4 address."
            done
            while true; do
                read -r -p "    Enter WAN Subnet CIDR Prefix (1-32) [24]: " WAN_CIDR
                WAN_CIDR="${WAN_CIDR:-24}"
                validate_cidr "$WAN_CIDR" 1 32 && break
                echo "    [!] Please enter a valid CIDR prefix between 1 and 32."
            done
            while true; do
                read -r -p "    Enter WAN Default Gateway IPv4: " WAN_GW
                validate_ipv4 "$WAN_GW" && break
                echo "    [!] Please enter a valid IPv4 gateway address."
            done
            while true; do
                read -r -p "    Enter WAN DNS Server(s) (comma-separated) [1.1.1.1,9.9.9.9]: " WAN_DNS
                WAN_DNS="${WAN_DNS:-1.1.1.1,9.9.9.9}"
                dns_ok=true
                IFS=', ' read -r -a wdns_arr <<< "$WAN_DNS"
                for d in "${wdns_arr[@]}"; do
                    [[ -z "$d" ]] && continue
                    if ! validate_ipv4 "$d"; then
                        dns_ok=false
                        break
                    fi
                done
                $dns_ok && break
                echo "    [!] Every DNS server must be a valid IPv4 address."
            done
            break
            ;;
        *)
            echo "    [!] Please enter 1 (DHCP) or 2 (Static)."
            ;;
    esac
done

# -----------------------------------------------------------------------------
# 2. Select LAN Interface, Subnet, and Router IP
# -----------------------------------------------------------------------------
DEFAULT_LAN=""
for dev in "${PHYS_IFACES[@]}"; do
    if [[ "$dev" != "$WAN_IFACE" ]]; then
        DEFAULT_LAN="$dev"
        break
    fi
done
DEFAULT_LAN="${DEFAULT_LAN:-${PHYS_IFACES[0]}}"

echo ""
while true; do
    read -r -p " 2. Select LAN (Internal Network) interface [${DEFAULT_LAN}]: " lan_input
    lan_input="${lan_input:-$DEFAULT_LAN}"
    if [[ "$lan_input" =~ ^[0-9]+$ ]] && (( lan_input >= 1 && lan_input <= ${#PHYS_IFACES[@]} )); then
        LAN_IFACE="${PHYS_IFACES[$((lan_input - 1))]}"
    elif printf '%s\n' "${PHYS_IFACES[@]}" | grep -qx "$lan_input"; then
        LAN_IFACE="$lan_input"
    elif [[ "$lan_input" =~ ^[a-zA-Z0-9_-]{1,15}$ ]]; then
        LAN_IFACE="$lan_input"
    else
        echo "    [!] Invalid selection. Enter a number (1-${#PHYS_IFACES[@]}) or interface name."
        continue
    fi

    if [[ "$LAN_IFACE" == "$WAN_IFACE" ]] && (( ${#PHYS_IFACES[@]} > 1 )); then
        echo "    [!] LAN interface cannot be the same as WAN interface (${WAN_IFACE})."
        continue
    fi
    break
done

while true; do
    read -r -p "    Enter LAN Router IPv4 Address (Gateway for LAN clients) [192.168.1.1]: " LAN_IP
    LAN_IP="${LAN_IP:-192.168.1.1}"
    validate_ipv4 "$LAN_IP" && break
    echo "    [!] Please enter a valid IPv4 address."
done

while true; do
    read -r -p "    Enter LAN Subnet CIDR Prefix (8-30) [24]: " LAN_CIDR
    LAN_CIDR="${LAN_CIDR:-24}"
    validate_cidr "$LAN_CIDR" 8 30 && break
    echo "    [!] Please enter a CIDR prefix between 8 and 30 (e.g. 24 for 255.255.255.0)."
done

LAN_NETMASK="$(cidr_to_netmask "$LAN_CIDR")"
LAN_PREFIX_3="${LAN_IP%.*}"

# -----------------------------------------------------------------------------
# 3. Configure DHCP Server Scope (dnsmasq)
# -----------------------------------------------------------------------------
echo ""
echo " 3. DHCP & DNS Configuration (for LAN '${LAN_IFACE}'):"
DEFAULT_DHCP_START="${LAN_PREFIX_3}.50"
DEFAULT_DHCP_END="${LAN_PREFIX_3}.200"

while true; do
    read -r -p "    DHCP Pool Start IP [${DEFAULT_DHCP_START}]: " DHCP_START
    DHCP_START="${DHCP_START:-$DEFAULT_DHCP_START}"
    validate_ipv4 "$DHCP_START" && break
    echo "    [!] Please enter a valid IPv4 address."
done

while true; do
    read -r -p "    DHCP Pool End IP [${DEFAULT_DHCP_END}]: " DHCP_END
    DHCP_END="${DHCP_END:-$DEFAULT_DHCP_END}"
    validate_ipv4 "$DHCP_END" && break
    echo "    [!] Please enter a valid IPv4 address."
done

while true; do
    read -r -p "    DHCP Lease Time (e.g. 24h, 12h, 7d) [24h]: " DHCP_LEASE
    DHCP_LEASE="${DHCP_LEASE:-24h}"
    [[ "$DHCP_LEASE" =~ ^(infinite|[0-9]{1,4}[smhdw])$ ]] && break
    echo "    [!] Enter a valid lease time such as 24h, 12h, or 7d."
done

while true; do
    read -r -p "    Local LAN Domain Name [home.arpa]: " LAN_DOMAIN
    LAN_DOMAIN="${LAN_DOMAIN:-home.arpa}"
    validate_domain "$LAN_DOMAIN" && break
    echo "    [!] Please enter a valid domain name (e.g. home.arpa or lan.local)."
done

while true; do
    read -r -p "    Upstream DNS Servers for dnsmasq [1.1.1.1,1.0.0.1,9.9.9.9]: " UPSTREAM_DNS_RAW
    UPSTREAM_DNS_RAW="${UPSTREAM_DNS_RAW:-1.1.1.1,1.0.0.1,9.9.9.9}"
    dns_ok=true
    UPSTREAM_DNS_LIST=()
    IFS=', ' read -r -a udns_arr <<< "$UPSTREAM_DNS_RAW"
    for d in "${udns_arr[@]}"; do
        [[ -z "$d" ]] && continue
        if ! validate_ipv4 "$d"; then
            dns_ok=false
            break
        fi
        UPSTREAM_DNS_LIST+=("$d")
    done
    if $dns_ok && (( ${#UPSTREAM_DNS_LIST[@]} > 0 )); then
        break
    fi
    echo "    [!] Please enter comma-separated valid IPv4 DNS addresses."
done

# -----------------------------------------------------------------------------
# 4. Review Summary & Confirm
# -----------------------------------------------------------------------------
echo ""
echo "========================================================================"
echo " Configuration Summary"
echo "========================================================================"
if [[ "$WAN_MODE" == "auto" ]]; then
    echo "  * WAN Interface:      ${WAN_IFACE} (DHCP Client)"
else
    echo "  * WAN Interface:      ${WAN_IFACE} (Static: ${WAN_IP}/${WAN_CIDR}, GW: ${WAN_GW})"
fi
echo "  * LAN Interface:      ${LAN_IFACE} (Static: ${LAN_IP}/${LAN_CIDR}, Mask: ${LAN_NETMASK})"
echo "  * DHCP Range (LAN):   ${DHCP_START} - ${DHCP_END} (Lease: ${DHCP_LEASE})"
echo "  * LAN Domain:         ${LAN_DOMAIN}"
echo "  * Upstream DNS:       ${UPSTREAM_DNS_LIST[*]}"
echo "  * WAN DHCP Protection: except-interface=${WAN_IFACE} enforced in dnsmasq"
echo "========================================================================"
echo ""
read -r -p " Apply this configuration now? [Y/n]: " confirm_apply
case "${confirm_apply:-Y}" in
    [nN][oO]|[nN])
        echo " Aborted without making changes."
        exit 0
        ;;
esac

echo ""
echo " ==> Writing NetworkManager profiles..."

cat > /etc/NetworkManager/system-connections/10-wan.nmconnection << EOF
[connection]
id=WAN
uuid=a6375bc1-5369-455b-bb43-e69493cf0001
type=ethernet
interface-name=${WAN_IFACE}
autoconnect=true
autoconnect-priority=100

[ethernet]

EOF

if [[ "$WAN_MODE" == "auto" ]]; then
    cat >> /etc/NetworkManager/system-connections/10-wan.nmconnection << EOF
[ipv4]
method=auto
never-default=false

[ipv6]
method=auto
addr-gen-mode=default
EOF
else
    WAN_DNS_SEMI="$(IFS=';'; echo "${wdns_arr[*]:-1.1.1.1;9.9.9.9}")"
    cat >> /etc/NetworkManager/system-connections/10-wan.nmconnection << EOF
[ipv4]
method=manual
address1=${WAN_IP}/${WAN_CIDR},${WAN_GW}
dns=${WAN_DNS_SEMI};
never-default=false

[ipv6]
method=auto
addr-gen-mode=default
EOF
fi

cat > /etc/NetworkManager/system-connections/20-lan.nmconnection << EOF
[connection]
id=LAN
uuid=b7486cd2-6470-566c-cc54-f70504df0002
type=ethernet
interface-name=${LAN_IFACE}
autoconnect=true
autoconnect-priority=50

[ethernet]

[ipv4]
address1=${LAN_IP}/${LAN_CIDR}
method=manual
never-default=true

[ipv6]
method=ignore
EOF

chmod 0600 /etc/NetworkManager/system-connections/10-wan.nmconnection \
           /etc/NetworkManager/system-connections/20-lan.nmconnection

echo " ==> Writing /etc/dnsmasq.conf (excluding WAN '${WAN_IFACE}' from DHCP/DNS)..."

UPSTREAM_SERVERS_BLOCK=""
for d in "${UPSTREAM_DNS_LIST[@]}"; do
    UPSTREAM_SERVERS_BLOCK+="server=${d}#53"$'\n'
done

cat > /etc/dnsmasq.conf << EOF
# /etc/dnsmasq.conf
# Azureclaw DHCP and DNS Caching Resolver (Generated by azureclaw-setup)

# -------------------------------------------------------------
# Interface & Binding Safety
# -------------------------------------------------------------
# Bind dynamically to avoid startup failures before interfaces are up
bind-dynamic

# Do NOT serve DHCP or respond to DNS queries on WAN interface
except-interface=${WAN_IFACE}

# Serve DHCP and DNS on LAN interface
interface=${LAN_IFACE}
listen-address=127.0.0.1
listen-address=::1
listen-address=${LAN_IP}

# -------------------------------------------------------------
# DNS Resolver Configuration
# -------------------------------------------------------------
domain-needed
bogus-priv
stop-dns-rebind
rebind-localhost-ok

# Local DNS domain
domain=${LAN_DOMAIN}
local=/${LAN_DOMAIN}/
expand-hosts
address=/azureclaw.${LAN_DOMAIN}/${LAN_IP}
address=/azureclaw/${LAN_IP}

cache-size=2500

# Upstream Public DNS Resolvers
${UPSTREAM_SERVERS_BLOCK}
# -------------------------------------------------------------
# DHCP Server Configuration (IPv4)
# -------------------------------------------------------------
dhcp-range=${DHCP_START},${DHCP_END},${LAN_NETMASK},${DHCP_LEASE}
dhcp-option=option:router,${LAN_IP}
dhcp-option=option:dns-server,${LAN_IP}
dhcp-option=option:domain-name,${LAN_DOMAIN}

# -------------------------------------------------------------
# Modular Configuration Snippets (/etc/dnsmasq.d/)
# -------------------------------------------------------------
conf-dir=/etc/dnsmasq.d
EOF
chmod 0644 /etc/dnsmasq.conf

echo " ==> Updating nftables WAN_IFACES (${WAN_IFACE}) and LAN_IFACES (${LAN_IFACE})..."
for nft_file in /etc/nftables/nftables.conf /etc/sysconfig/nftables.conf; do
    if [[ -f "$nft_file" ]]; then
        sed -i -E "s|^define WAN_IFACES = \{.*\}|define WAN_IFACES = { \"${WAN_IFACE}\" }|" "$nft_file"
        sed -i -E "s|^define LAN_IFACES = \{.*\}|define LAN_IFACES = { \"${LAN_IFACE}\" }|" "$nft_file"
    fi
done

echo " ==> Applying NetworkManager, nftables, and dnsmasq services..."
nmcli connection reload || true
nmcli connection up WAN || true
nmcli connection up LAN || true

if nft -c -f /etc/nftables/nftables.conf; then
    systemctl reload nftables || systemctl restart nftables || true
else
    echo " [!] WARNING: nftables config check reported an issue." >&2
fi

if dnsmasq --test; then
    systemctl restart dnsmasq
else
    echo " [!] ERROR: dnsmasq configuration test failed!" >&2
    exit 1
fi

touch "$MARKER"

echo ""
echo "========================================================================"
echo " [✓] Onboarding setup complete!"
echo "     WAN: ${WAN_IFACE} (${WAN_MODE})"
echo "     LAN: ${LAN_IFACE} (${LAN_IP}/${LAN_CIDR})"
echo "     DHCP: ${DHCP_START} - ${DHCP_END} on ${LAN_IFACE}"
echo "     (Re-run anytime with: sudo azureclaw-setup)"
echo "========================================================================"
echo ""
