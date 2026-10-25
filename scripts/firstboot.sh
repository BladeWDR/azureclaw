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

# 2. Generate a cryptographically random 16-character temporary password
TEMP_PASS=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)

# Set the password and expire it immediately (forces password change on login)
echo "admin:${TEMP_PASS}" | chpasswd
chage -d 0 admin

# 3. Format console banner right above the login prompt
# In Fedora bootc, /etc/issue is a symlink pointing to /usr/lib/issue (read-only).
# Unlink it first so we can write a local issue file in /etc, and write to /etc/issue.d/
rm -f /etc/issue
mkdir -p /etc/issue.d

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

echo "${BANNER}" > /etc/issue
echo "${BANNER}" > /etc/issue.d/10-azureclaw.issue

# Broadcast to all active terminals so it is visible immediately on screen
for term in /dev/console /dev/tty0 /dev/tty1 /dev/ttyS0; do
    if [ -w "${term}" ] 2>/dev/null; then
        echo "${BANNER}" > "${term}" 2>/dev/null || true
    fi
done

touch "${MARKER}"
