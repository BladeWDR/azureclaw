#!/usr/bin/env bash
# /etc/profile.d/99-azureclaw-status.sh
# Run first-login onboarding wizard if not yet completed, then display live router status
if [ -t 0 ] && [ -t 1 ] && [ -n "${PS1:-}" ]; then
    rm -f /run/issue.d/10-azureclaw.issue 2>/dev/null || true
    if [ ! -f /var/lib/azureclaw/onboarding.done ] && [ -x /usr/libexec/azureclaw/onboarding-wizard.sh ]; then
        /usr/libexec/azureclaw/onboarding-wizard.sh --first-login || true
    fi
    if [ -x /usr/libexec/azureclaw/router-status.sh ]; then
        /usr/libexec/azureclaw/router-status.sh
    fi
fi
