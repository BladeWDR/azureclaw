#!/usr/bin/env bash
# /usr/libexec/azureclaw/firstboot-cleanup.sh
# Invoked via PAM (pam_exec.so) on successful login as root
# Cleans temporary first-boot credentials from /etc/issue and /etc/issue.d
set -euo pipefail

rm -f /run/issue.d/10-azureclaw.issue /etc/issue.d/10-azureclaw.issue 2>/dev/null || true

if grep -q "First-Boot Random Credential" /etc/issue 2>/dev/null; then
    if [ -f /usr/lib/issue ]; then
        ln -sf ../usr/lib/issue /etc/issue 2>/dev/null || rm -f /etc/issue 2>/dev/null || true
    else
        rm -f /etc/issue 2>/dev/null || true
    fi
fi
