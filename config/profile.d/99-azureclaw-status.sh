#!/usr/bin/env bash
# /etc/profile.d/99-azureclaw-status.sh
# Display live interface status & network addresses on interactive login
if [ -t 1 ] && [ -n "${PS1:-}" ] && [ -x /usr/libexec/azureclaw/router-status.sh ]; then
    /usr/libexec/azureclaw/router-status.sh
fi
