#!/usr/bin/env bash
# /usr/libexec/azureclaw/firstboot-cleanup.sh
# Invoked via PAM (pam_exec.so) on successful login as root
# Cleans temporary first-boot credentials from /etc/issue and /etc/issue.d
set -euo pipefail

if [ -f /etc/issue.d/10-azureclaw.issue ] || grep -q "First-Boot Random Credential" /etc/issue 2>/dev/null; then
    rm -f /etc/issue.d/10-azureclaw.issue 2>/dev/null || true
    if [ -f /etc/motd ]; then
        cp -f /etc/motd /etc/issue 2>/dev/null || true
    fi
fi
