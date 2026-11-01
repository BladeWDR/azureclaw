#!/usr/bin/env bash
# /usr/libexec/azureclaw/firstboot.sh
# First-boot security provisioning for Azureclaw
set -euo pipefail

MARKER="/var/lib/azureclaw/firstboot.done"
mkdir -p /var/lib/azureclaw

if [ -f "${MARKER}" ]; then
    exit 0
fi

# 1. If an SSH key already exists (baked-in or via Cloud-Init), keep password locked
if [ -s /home/admin/.ssh/authorized_keys ]; then
    echo "Azureclaw: SSH key detected. Keeping console password locked." > /dev/console 2>/dev/null || true
    touch "${MARKER}"
    exit 0
fi

# 2. Generate a random 8-character temporary password using unambiguous characters
# Excludes 0/O/o, 1/l/I, and uppercase/lowercase lookalikes that are hard to distinguish on VGA console fonts
TEMP_PASS=$(head -c 512 /dev/urandom | tr -dc 'abcdefghjkmnpqrstuvwxyz23456789' | head -c 8)

# Set the password and expire it immediately (forces password change on login)
echo "admin:${TEMP_PASS}" | chpasswd
chage -d 0 admin

# 3. Format console banner right above the login prompt
# Write to volatile /run/issue.d/ (mode 0666 in sticky dir) so it is automatically
# cleared on login (even by non-root profile scripts) and never persists across reboots.
mkdir -p /run/issue.d
chmod 1777 /run/issue.d

BANNER="
========================================================================
   __ _ _____   _ _ __ ___  ___| | __ ___      __
  / _\` |_  / | | | '__/ _ \/ __| |/ _\` \ \ /\ / /
 | (_| |/ /| |_| | | |  __/ (__| | (_| |\ V  V / 
  \__,_/___|\__,_|_|  \___|\___|_|\__,_| \_/\_/  
       First-Boot Random Credential Generation
========================================================================
 [!] A unique, temporary password was generated for console user 'admin':

     Username: admin
     Password: ${TEMP_PASS}

 [!] You will be REQUIRED to set your permanent password upon logging in.
========================================================================
"

echo "${BANNER}" > /run/issue.d/10-azureclaw.issue
chmod 0666 /run/issue.d/10-azureclaw.issue

touch "${MARKER}"
