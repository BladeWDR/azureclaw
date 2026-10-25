#!/usr/bin/env bash
# /etc/profile.d/azureclaw-cleanup.sh
# Cleans temporary first-boot credentials from /etc/issue after initial login

if grep -q "First-Boot Random Credential" /etc/issue /etc/issue.d/10-azureclaw.issue 2>/dev/null; then
    rm -f /etc/issue.d/10-azureclaw.issue 2>/dev/null || true
    cat << 'EOF' > /etc/issue

========================================================================
   __ _ _____   _ _ __ ___  ___| | __ ___      __
  / _` |_  / | | | '__/ _ \/ __| |/ _` \ \ /\ / /
 | (_| |/ /| |_| | | |  __/ (__| | (_| |\ V  V / 
  \__,_/___|\__,_|_|  \___|\___|_|\__,_| \_/\_/  
         Immutable Home Router (bootc / Fedora)
========================================================================

\S
Kernel \r on an \m (\l)

EOF
fi
