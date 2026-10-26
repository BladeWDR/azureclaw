#!/usr/bin/env bash
# /etc/NetworkManager/dispatcher.d/99-azureclaw-issue.sh
# Update pre-login console screen whenever network interfaces or IPs change
if [ -x /usr/libexec/azureclaw/router-status.sh ]; then
    mkdir -p /run/issue.d
    /usr/libexec/azureclaw/router-status.sh > /run/issue.d/90-network.issue 2>/dev/null || true
fi
