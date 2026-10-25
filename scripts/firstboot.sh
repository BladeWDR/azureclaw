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

# 3. Format console banner in /etc/issue right above the login prompt
cat << EOF > /etc/issue

========================================================================
   __ _ _____   _ _ __ ___  ___| | __ ___      __
  / _` |_  / | | | '__/ _ \/ __| |/ _` \ \ /\ / /
 | (_| |/ /| |_| | | |  __/ (__| | (_| |\ V  V / 
  \__,_/___|\__,_|_|  \___|\___|_|\__,_| \_/\_/  
       First-Boot Random Credential Generation
========================================================================
 [!] A unique, temporary password was generated for console user 'admin':

     Username: admin
     Password: ${TEMP_PASS}

 [!] You will be REQUIRED to set your permanent password upon logging in.
========================================================================

\S
Kernel \r on an \m (\l)

EOF

echo "Azureclaw: Generated one-time password for admin: ${TEMP_PASS}" > /dev/console 2>/dev/null || true
touch "${MARKER}"
