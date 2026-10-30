#!/usr/bin/env bash
# /usr/libexec/azureclaw/router-status.sh
# Dynamic network interface & system status display for Azureclaw
set -euo pipefail

# 1. Header Banner
cat << 'EOF'
========================================================================
   __ _ _____   _ _ __ ___  ___| | __ ___      __
  / _` |_  / | | | '__/ _ \/ __| |/ _` \ \ /\ / /
 | (_| |/ /| |_| | | |  __/ (__| | (_| |\ V  V / 
  \__,_/___|\__,_|_|  \___|\___|_|\__,_| \_/\_/  
         Immutable Router (bootc / Fedora)
========================================================================
EOF

# 2. Helper to determine connection profile / role
get_conn_name() {
    local dev="${1%%@*}"
    local conn=""
    if command -v nmcli >/dev/null 2>&1; then
        conn=$(nmcli -t -f DEVICE,CONNECTION device 2>/dev/null | awk -F: -v d="$dev" '$1==d {print $2; exit}')
    fi
    if [ -z "$conn" ] || [ "$conn" = "--" ]; then
        if [ "$dev" = "ens18" ] || [ "$dev" = "eth0" ]; then conn="WAN"
        elif [ "$dev" = "ens19" ] || [ "$dev" = "eth1" ]; then conn="LAN"
        elif [[ "$dev" =~ ([vV][lL][aA][nN]|\.[0-9]+$) ]]; then conn="VLAN"
        elif [ "$dev" = "tailscale0" ]; then conn="Tailscale"
        elif [[ "$dev" =~ ^wg ]]; then conn="WireGuard"
        elif [[ "$dev" =~ ^(tun|tap) ]]; then conn="OpenVPN"
        elif [[ "$dev" =~ ^(ppp|ipsec|xfrm) ]]; then conn="IPsec/L2TP"
        else conn="Other"
        fi
    fi
    echo "$conn"
}

# 3. Interfaces Table
printf " %-12s %-16s %-8s %-32s\n" "INTERFACE" "ROLE/NAME" "STATUS" "ADDRESS(ES)"
printf " %-12s %-16s %-8s %-32s\n" "---------" "---------" "------" "-----------"

lan_ip="192.168.1.1"

while read -r iface state addrs; do
    [ -z "$iface" ] || [ "$iface" = "lo" ] && continue
    [[ "$iface" =~ ^(docker|veth|br-) ]] && continue
    
    clean_iface="${iface%%@*}"
    role=$(get_conn_name "$clean_iface")
    clean_ips=""
    for ip in $addrs; do
        if [[ ! "$ip" =~ ^fe80: ]]; then
            clean_ips="${clean_ips:+$clean_ips, }$ip"
            if [[ "$role" =~ ^LAN ]] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
                lan_ip="${ip%%/*}"
            fi
        fi
    done
    [ -z "$clean_ips" ] && clean_ips="No IP assigned"

    printf " %-12s %-16s %-8s %-32s\n" "$clean_iface" "$role" "$state" "$clean_ips"
done < <(ip -br addr 2>/dev/null || true)

# 4. Footer & Quick Management Info
cat << EOF
========================================================================
 * Cockpit Web UI:     https://${lan_ip}:9090
 * Grafana Alloy:      http://${lan_ip}:12345 (Metrics & UI)
 * OS Updates:         bootc upgrade [--apply]
 * Firewall Status:    nft list ruleset
========================================================================
EOF
