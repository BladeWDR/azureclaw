#!/usr/bin/env bash
# /usr/libexec/azureclaw/deploy-cockpit-cert.sh
# Certbot deploy hook (/etc/letsencrypt/renewal-hooks/deploy/50-cockpit-cert.sh)
# Automatically installs issued/renewed Let's Encrypt certificates into Cockpit (:9090).
set -euo pipefail

LINEAGE="${RENEWED_LINEAGE:-${1:-}}"

if [[ -z "$LINEAGE" ]]; then
    # Fall back to the first directory in /etc/letsencrypt/live/ containing fullchain.pem
    for dir in /etc/letsencrypt/live/*; do
        if [[ -d "$dir" && -f "$dir/fullchain.pem" && -f "$dir/privkey.pem" ]]; then
            LINEAGE="$dir"
            break
        fi
    done
fi

if [[ -z "$LINEAGE" || ! -f "$LINEAGE/fullchain.pem" || ! -f "$LINEAGE/privkey.pem" ]]; then
    echo "[azureclaw-certbot] No valid certificate lineage found to deploy to Cockpit." >&2
    exit 0
fi

CERT_DIR="/etc/cockpit/ws-certs.d"
mkdir -p "$CERT_DIR"

install -m 0644 -o root -g root "$LINEAGE/fullchain.pem" "$CERT_DIR/99-letsencrypt.cert"
if getent group cockpit-wsinstance >/dev/null 2>&1; then
    install -m 0640 -o root -g cockpit-wsinstance "$LINEAGE/privkey.pem" "$CERT_DIR/99-letsencrypt.key"
elif getent group cockpit-ws >/dev/null 2>&1; then
    install -m 0640 -o root -g cockpit-ws "$LINEAGE/privkey.pem" "$CERT_DIR/99-letsencrypt.key"
else
    install -m 0600 -o root -g root "$LINEAGE/privkey.pem" "$CERT_DIR/99-letsencrypt.key"
fi

systemctl try-restart cockpit.service || true
echo "[azureclaw-certbot] Deployed TLS certificate from $LINEAGE to $CERT_DIR/99-letsencrypt.{cert,key}."
