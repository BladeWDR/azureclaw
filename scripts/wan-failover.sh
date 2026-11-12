#!/usr/bin/env bash
# /usr/libexec/azureclaw/wan-failover.sh
# Azureclaw Multi-WAN Active/Backup Reachability Watchdog
# Monitors upstream ISP reachability on PRIMARY_WAN_IFACE and dynamically adjusts
# default route metrics and conntrack state to fail over to BACKUP_WAN_IFACE.

set -euo pipefail

CONF_FILE="/etc/azureclaw/multiwan.conf"

# Defaults
MULTIWAN_ENABLED="false"
PRIMARY_WAN_IFACE="ens18"
PRIMARY_WAN_CON="WAN"
BACKUP_WAN_IFACE="ens20"
BACKUP_WAN_CON="WAN2"
CHECK_TARGETS="1.1.1.1 9.9.9.9"
CHECK_INTERVAL="15"
FAIL_THRESHOLD="3"
RECOVERY_THRESHOLD="3"
PRIMARY_METRIC="100"
BACKUP_METRIC="200"
DEMOTED_METRIC="500"

load_config() {
    if [[ -f "$CONF_FILE" ]]; then
        while IFS='=' read -r raw_key raw_val; do
            local key val
            key="$(echo "${raw_key%%#*}" | tr -d '[:space:]')"
            [[ -z "$key" ]] && continue
            val="$(echo "${raw_val%%#*}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
            case "$key" in
                MULTIWAN_ENABLED)   MULTIWAN_ENABLED="$val" ;;
                PRIMARY_WAN_IFACE)  PRIMARY_WAN_IFACE="$val" ;;
                PRIMARY_WAN_CON)    PRIMARY_WAN_CON="$val" ;;
                BACKUP_WAN_IFACE)   BACKUP_WAN_IFACE="$val" ;;
                BACKUP_WAN_CON)     BACKUP_WAN_CON="$val" ;;
                CHECK_TARGETS)      CHECK_TARGETS="$val" ;;
                CHECK_INTERVAL)     CHECK_INTERVAL="$val" ;;
                FAIL_THRESHOLD)     FAIL_THRESHOLD="$val" ;;
                RECOVERY_THRESHOLD) RECOVERY_THRESHOLD="$val" ;;
                PRIMARY_METRIC)     PRIMARY_METRIC="$val" ;;
                BACKUP_METRIC)      BACKUP_METRIC="$val" ;;
                DEMOTED_METRIC)     DEMOTED_METRIC="$val" ;;
            esac
        done < "$CONF_FILE"
    fi
}

load_config

if [[ "${MULTIWAN_ENABLED,,}" != "true" ]]; then
    echo "[azureclaw-multiwan] Multi-WAN failover is disabled in $CONF_FILE."
    exit 0
fi

# Apply Loose Reverse Path Filtering (rp_filter = 2) ONLY on the WAN interfaces
# so return packets on asymmetric/standby WAN paths are accepted while LAN/VLANs keep Strict mode (1).
for iface in "$PRIMARY_WAN_IFACE" "$BACKUP_WAN_IFACE"; do
    if [[ -d "/proc/sys/net/ipv4/conf/${iface}" ]]; then
        sysctl -qw "net.ipv4.conf.${iface}.rp_filter=2" || true
    fi
done

# Ensure baseline route metrics on both WAN connections
nmcli connection modify "$PRIMARY_WAN_CON" ipv4.route-metric "$PRIMARY_METRIC" 2>/dev/null || true
nmcli connection modify "$BACKUP_WAN_CON" ipv4.route-metric "$BACKUP_METRIC" 2>/dev/null || true
nmcli device modify "$PRIMARY_WAN_IFACE" ipv4.route-metric "$PRIMARY_METRIC" 2>/dev/null || true
nmcli device modify "$BACKUP_WAN_IFACE" ipv4.route-metric "$BACKUP_METRIC" 2>/dev/null || true

get_wan_gateway() {
    local dev="$1"
    ip -4 route show dev "$dev" default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}'
}

probe_primary_wan() {
    # Verify physical link is UP and has an IPv4 gateway
    local oper gw
    oper="$(cat "/sys/class/net/${PRIMARY_WAN_IFACE}/operstate" 2>/dev/null || echo "down")"
    if [[ "${oper,,}" != "up" ]]; then
        return 1
    fi

    gw="$(get_wan_gateway "$PRIMARY_WAN_IFACE")"
    if [[ -z "$gw" ]]; then
        return 1
    fi

    local target
    for target in $CHECK_TARGETS; do
        # Pin a temporary /32 route out PRIMARY_WAN_IFACE so probes test PRIMARY_WAN_IFACE
        # even when PRIMARY_WAN_IFACE is currently demoted to DEMOTED_METRIC (500).
        ip -4 route replace "${target}/32" via "$gw" dev "$PRIMARY_WAN_IFACE" metric 5 2>/dev/null || true
        if ping -I "$PRIMARY_WAN_IFACE" -c 1 -W 2 -q "$target" >/dev/null 2>&1; then
            ip -4 route del "${target}/32" via "$gw" dev "$PRIMARY_WAN_IFACE" metric 5 2>/dev/null || true
            return 0
        fi
        ip -4 route del "${target}/32" via "$gw" dev "$PRIMARY_WAN_IFACE" metric 5 2>/dev/null || true
    done

    return 1
}

set_primary_metric() {
    local new_metric="$1"
    if ! nmcli device modify "$PRIMARY_WAN_IFACE" ipv4.route-metric "$new_metric" 2>/dev/null; then
        local gw
        gw="$(get_wan_gateway "$PRIMARY_WAN_IFACE")"
        if [[ -n "$gw" ]]; then
            ip -4 route replace default via "$gw" dev "$PRIMARY_WAN_IFACE" metric "$new_metric" 2>/dev/null || true
        fi
    fi
    conntrack -F >/dev/null 2>&1 || true
}

echo "[azureclaw-multiwan] Monitoring Primary WAN '${PRIMARY_WAN_IFACE}' (metric ${PRIMARY_METRIC}) with Backup WAN '${BACKUP_WAN_IFACE}' (metric ${BACKUP_METRIC})..."

STATE="primary"
FAIL_COUNT=0
RECOVER_COUNT=0

while true; do
    if probe_primary_wan; then
        FAIL_COUNT=0
        if [[ "$STATE" == "backup" ]]; then
            ((RECOVER_COUNT += 1))
            echo "[azureclaw-multiwan] Primary WAN '${PRIMARY_WAN_IFACE}' probe succeeded (${RECOVER_COUNT}/${RECOVERY_THRESHOLD})."
            if (( RECOVER_COUNT >= RECOVERY_THRESHOLD )); then
                echo "[azureclaw-multiwan] RECOVERY: Restoring Primary WAN '${PRIMARY_WAN_IFACE}' to metric ${PRIMARY_METRIC}."
                set_primary_metric "$PRIMARY_METRIC"
                STATE="primary"
                RECOVER_COUNT=0
            fi
        fi
    else
        RECOVER_COUNT=0
        if [[ "$STATE" == "primary" ]]; then
            ((FAIL_COUNT += 1))
            echo "[azureclaw-multiwan] WARNING: Primary WAN '${PRIMARY_WAN_IFACE}' probe failed (${FAIL_COUNT}/${FAIL_THRESHOLD})." >&2
            if (( FAIL_COUNT >= FAIL_THRESHOLD )); then
                echo "[azureclaw-multiwan] FAILOVER: Demoting Primary WAN '${PRIMARY_WAN_IFACE}' to metric ${DEMOTED_METRIC}; activating Backup WAN '${BACKUP_WAN_IFACE}'." >&2
                set_primary_metric "$DEMOTED_METRIC"
                STATE="backup"
                FAIL_COUNT=0
            fi
        fi
    fi

    sleep "$CHECK_INTERVAL"
done
