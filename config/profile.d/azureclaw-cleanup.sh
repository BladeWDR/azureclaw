#!/usr/bin/env bash
# /etc/profile.d/azureclaw-cleanup.sh
# Cleans temporary first-boot credentials from /etc/issue after initial login

if grep -q "First-Boot Random Credential" /etc/issue /etc/issue.d/10-azureclaw.issue 2>/dev/null; then
    if [ "$(id -u)" -eq 0 ]; then
        rm -f /etc/issue.d/10-azureclaw.issue 2>/dev/null || true
        cat /etc/motd > /etc/issue 2>/dev/null || true
    elif command -v sudo >/dev/null 2>&1; then
        sudo rm -f /etc/issue.d/10-azureclaw.issue 2>/dev/null || true
        sudo cp -f /etc/motd /etc/issue 2>/dev/null || true
    fi
fi
